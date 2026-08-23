package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hightemp/go_port_scanner/internal/cli"
	appconfig "github.com/hightemp/go_port_scanner/internal/config"
	"github.com/hightemp/go_port_scanner/internal/discovery"
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
	if err := validateReportDestination(configuration, options.ConfigPath); err != nil {
		return fmt.Errorf("validate report: %w", err)
	}
	targets, err := configuration.ExpandedTargets()
	if err != nil {
		return fmt.Errorf("expand targets: %w", err)
	}
	ports := configuration.ExpandedPorts()

	requestedTargets := append([]string(nil), targets...)
	logger := logging.New(reportLogOutput(configuration, stdout, stderr), logging.Level(configuration.VerbosityLevel()))
	scanContext := ctx
	if configuration.Scanner.ScanTimeout.Duration > 0 {
		var cancel context.CancelFunc
		scanContext, cancel = context.WithTimeout(ctx, configuration.Scanner.ScanTimeout.Duration)
		defer cancel()
	}
	startedAt := time.Now()
	var discoveryResults []discovery.Result
	hostnames := make(map[string]string)
	if configuration.ReverseDNS.Enabled {
		hostnames, err = resolveHostnames(
			scanContext,
			logger,
			targets,
			configuration.ReverseDNS,
			nil,
		)
		if err != nil {
			return err
		}
	}

	var scanDialer scanner.Dialer
	if configuration.Proxy.Enabled {
		proxyPool, err := proxypool.New(proxypool.Config{
			URLs:                  configuration.Proxy.URLs,
			Strategy:              proxypool.Strategy(configuration.Proxy.Strategy),
			Timeout:               configuration.Scanner.DialTimeout.Duration,
			TLSInsecureSkipVerify: configuration.Proxy.TLSInsecureSkipVerify,
			Reporter: func(selection proxypool.Selection) {
				logger.Tracef(
					"Selected proxy %s using %s for %s %s\n",
					selection.Proxy,
					selection.Strategy,
					selection.Network,
					selection.Target,
				)
			},
		})
		if err != nil {
			return fmt.Errorf("configure proxy pool: %w", err)
		}
		scanDialer = proxyPool
		logger.Infof("Proxy pool enabled with %d proxies (%s)\n", proxyPool.Len(), proxyPool.Strategy())
	}

	if configuration.Discovery.Enabled &&
		configuration.Discovery.Strategy != appconfig.DiscoveryStrategyNone {
		discoveryStartedAt := time.Now()
		logger.Infof(
			"Discovering %d target(s) with %s strategy and %d workers\n",
			len(targets),
			configuration.Discovery.Strategy,
			configuration.Discovery.Workers,
		)
		hostDiscoverer, err := discovery.New(discovery.Config{
			Strategy: discovery.Strategy(configuration.Discovery.Strategy),
			Ports:    configuration.ExpandedDiscoveryPorts(),
			Workers:  configuration.Discovery.Workers,
			Timeout:  configuration.Discovery.Timeout.Duration,
			Dialer:   scanDialer,
			Reporter: newDiscoveryReporter(logger),
		})
		if err != nil {
			return fmt.Errorf("configure host discovery: %w", err)
		}
		results, err := hostDiscoverer.Discover(scanContext, targets)
		if err != nil {
			return fmt.Errorf("run host discovery: %w", err)
		}
		discoveryResults = results

		reachableTargets, err := filterDiscoveryResults(logger, results)
		logger.Infof(
			"Host discovery completed in %v: %d reachable, %d unavailable\n",
			time.Since(discoveryStartedAt),
			len(reachableTargets),
			len(results)-len(reachableTargets),
		)
		if err != nil {
			return err
		}
		targets = reachableTargets
	}

	logger.Infof(
		"Starting scan of %d target(s), %d port(s) with %d workers\n",
		len(targets),
		len(ports),
		configuration.Scanner.Workers,
	)

	probeRegistry, err := newProbeRegistry(configuration)
	if err != nil {
		return fmt.Errorf("configure protocol probes: %w", err)
	}
	if probeRegistry != nil {
		logger.Infof("Protocol probes enabled with %d protocol/port mapping(s)\n", probeRegistry.Count())
	}

	portScanner, err := scanner.New(scanner.Config{
		Targets:     targets,
		Ports:       ports,
		Workers:     configuration.Scanner.Workers,
		DialTimeout: configuration.Scanner.DialTimeout.Duration,
		Dialer:      scanDialer,
		Probes:      probeRegistry,
	})
	if err != nil {
		return fmt.Errorf("configure scanner: %w", err)
	}

	if portScanner.Workers() != configuration.Scanner.Workers {
		logger.Debugf("Adjusted workers count to %d\n", portScanner.Workers())
	}

	logger.Debugf("Starting %d workers...\n", portScanner.Workers())
	logger.Debugf("Sending %d checks to workers...\n", portScanner.Checks())

	scanStartedAt := time.Now()
	statistics := newScanStats(portScanner.Checks())
	openEvents := make([]scanner.Event, 0)
	var progressTicker *time.Ticker
	var progress <-chan time.Time
	if configuration.Scanner.ProgressInterval.Duration > 0 {
		progressTicker = time.NewTicker(configuration.Scanner.ProgressInterval.Duration)
		progress = progressTicker.C
		defer progressTicker.Stop()
	}

	events := portScanner.Scan(scanContext)
	for events != nil {
		select {
		case event, open := <-events:
			if !open {
				events = nil
				continue
			}
			statistics.observe(event)
			if event.Kind == scanner.EventOpen {
				openEvents = append(openEvents, event)
			}
			handleScanEvent(logger, event, len(targets) > 1, hostnames[event.Host])
		case <-progress:
			statistics.logProgress(logger, time.Since(scanStartedAt))
		}
	}

	finishedAt := time.Now()
	statistics.logSummary(logger, finishedAt.Sub(scanStartedAt))
	scanError := scanContext.Err()
	var resultError error
	if scanError != nil {
		resultError = fmt.Errorf("scan interrupted: %w", scanError)
		logger.Infof("Scan interrupted after %v\n", finishedAt.Sub(startedAt))
	} else {
		logger.Debugf("Finished sending ports\n")
		logger.Infof("Scan completed in %v\n", finishedAt.Sub(startedAt))
	}

	document := buildReportDocument(
		startedAt,
		finishedAt,
		requestedTargets,
		targets,
		len(ports),
		discoveryResults,
		openEvents,
		statistics,
		scanError,
		hostnames,
	)
	if err := writeConfiguredReport(configuration, document, stdout, stderr); err != nil {
		resultError = errors.Join(resultError, err)
	} else if configuration.Report.Enabled {
		logger.Infof(
			"Report written to %s in %s format\n",
			configuration.Report.Destination,
			configuration.Report.Format,
		)
	}
	if err := logger.Err(); err != nil {
		resultError = errors.Join(resultError, err)
	}
	return resultError
}

func handleScanEvent(logger *logging.Logger, event scanner.Event, multipleTargets bool, hostname string) {
	switch event.Kind {
	case scanner.EventChecking:
		logger.Tracef("Checking %s port %d...\n", event.Host, event.Port)
	case scanner.EventOpen:
		logger.Printf("%s\n", formatOpenEvent(event, multipleTargets, hostname))
		logger.Debugf(
			"Connection established to %s port %d in %v\n",
			event.Host,
			event.Port,
			event.Duration,
		)
		for _, result := range event.Probes {
			if result.Err != nil {
				logger.Debugf(
					"%s handshake with %s port %d failed in %v: %v\n",
					result.Protocol,
					event.Host,
					event.Port,
					result.Duration,
					result.Err,
				)
				continue
			}
			logger.Debugf(
				"%s handshake with %s port %d succeeded in %v: %s\n",
				result.Protocol,
				event.Host,
				event.Port,
				result.Duration,
				result.Detail,
			)
		}
		if event.Err != nil {
			logger.Debugf("Could not close connection to %s port %d: %v\n", event.Host, event.Port, event.Err)
		}
	case scanner.EventClosed:
		logger.Tracef("%s port %d is closed (%v)\n", event.Host, event.Port, event.Err)
	}
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
