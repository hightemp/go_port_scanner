package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/hightemp/go_port_scanner/internal/cli"
	appconfig "github.com/hightemp/go_port_scanner/internal/config"
	"github.com/hightemp/go_port_scanner/internal/logging"
	"github.com/hightemp/go_port_scanner/internal/proxypool"
	"github.com/hightemp/go_port_scanner/internal/scanner"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	options, err := cli.Parse(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("parse arguments: %w", err)
	}

	configuration, err := loadConfig(options)
	if err != nil {
		return err
	}
	ports := configuration.ExpandedPorts()

	logger := logging.New(stdout, logging.Level(configuration.VerbosityLevel()))
	logger.Infof(
		"Starting scan of %d target(s), %d port(s) with %d workers\n",
		len(configuration.Targets),
		len(ports),
		configuration.Scanner.Workers,
	)

	var scanDialer scanner.Dialer
	if configuration.Proxy.Enabled {
		proxyPool, err := proxypool.New(proxypool.Config{
			URLs:                  configuration.Proxy.URLs,
			Strategy:              proxypool.Strategy(configuration.Proxy.Strategy),
			Timeout:               configuration.Scanner.DialTimeout.Duration,
			TLSInsecureSkipVerify: configuration.Proxy.TLSInsecureSkipVerify,
		})
		if err != nil {
			return fmt.Errorf("configure proxy pool: %w", err)
		}
		scanDialer = proxyPool
		logger.Infof("Proxy pool enabled with %d proxies (%s)\n", proxyPool.Len(), proxyPool.Strategy())
	}

	portScanner, err := scanner.New(scanner.Config{
		Targets:     configuration.Targets,
		Ports:       ports,
		Workers:     configuration.Scanner.Workers,
		DialTimeout: configuration.Scanner.DialTimeout.Duration,
		Dialer:      scanDialer,
	})
	if err != nil {
		return fmt.Errorf("configure scanner: %w", err)
	}

	if portScanner.Workers() != configuration.Scanner.Workers {
		logger.Debugf("Adjusted workers count to %d\n", portScanner.Workers())
	}

	scanContext := ctx
	if configuration.Scanner.ScanTimeout.Duration > 0 {
		var cancel context.CancelFunc
		scanContext, cancel = context.WithTimeout(ctx, configuration.Scanner.ScanTimeout.Duration)
		defer cancel()
	}

	startedAt := time.Now()
	logger.Debugf("Starting %d workers...\n", portScanner.Workers())
	logger.Debugf("Sending %d checks to workers...\n", portScanner.Checks())

	for event := range portScanner.Scan(scanContext) {
		switch event.Kind {
		case scanner.EventChecking:
			logger.Tracef("Checking %s port %d...\n", event.Host, event.Port)
		case scanner.EventOpen:
			if len(configuration.Targets) == 1 {
				logger.Printf("TCP: %d\n", event.Port)
			} else {
				logger.Printf("TCP: %s\n", net.JoinHostPort(event.Host, strconv.Itoa(event.Port)))
			}
			logger.Debugf(
				"Connection established to %s port %d in %v\n",
				event.Host,
				event.Port,
				event.Duration,
			)
			if event.Err != nil {
				logger.Debugf("Could not close connection to %s port %d: %v\n", event.Host, event.Port, event.Err)
			}
		case scanner.EventClosed:
			logger.Tracef("%s port %d is closed (%v)\n", event.Host, event.Port, event.Err)
		}
	}

	if err := scanContext.Err(); err != nil {
		return fmt.Errorf("scan interrupted: %w", err)
	}

	logger.Debugf("Finished sending ports\n")
	logger.Infof("Scan completed in %v\n", time.Since(startedAt))
	if err := logger.Err(); err != nil {
		return err
	}
	return nil
}

func loadConfig(options cli.Options) (appconfig.Config, error) {
	configuration := appconfig.Default()
	if options.ConfigPath != "" {
		loaded, err := appconfig.Load(options.ConfigPath)
		if err != nil {
			return appconfig.Config{}, err
		}
		configuration = loaded
	}

	if options.Host != nil {
		configuration.Targets = []string{*options.Host}
	}
	if options.StartPort != nil && options.EndPort != nil {
		configuration.Ports = []appconfig.PortRange{{
			Start: *options.StartPort,
			End:   *options.EndPort,
		}}
	}
	if options.Workers != nil {
		configuration.Scanner.Workers = *options.Workers
	}
	if options.DialTimeout != nil {
		configuration.Scanner.DialTimeout.Duration = *options.DialTimeout
	}
	if options.ScanTimeout != nil {
		configuration.Scanner.ScanTimeout.Duration = *options.ScanTimeout
	}
	if options.Verbosity != nil {
		configuration.Scanner.Verbosity = verbosity(*options.Verbosity)
	}

	if err := configuration.Validate(); err != nil {
		return appconfig.Config{}, fmt.Errorf("validate config: %w", err)
	}
	return configuration, nil
}

func verbosity(level int) appconfig.Verbosity {
	switch level {
	case 1:
		return appconfig.VerbosityInfo
	case 2:
		return appconfig.VerbosityDebug
	case 3:
		return appconfig.VerbosityTrace
	default:
		return appconfig.VerbosityQuiet
	}
}
