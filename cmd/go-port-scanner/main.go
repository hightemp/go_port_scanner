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
	"github.com/hightemp/go_port_scanner/internal/logging"
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

	logger := logging.New(stdout, logging.Level(options.Verbosity))
	logger.Infof(
		"Starting scan of %s (ports %d-%d) with %d workers\n",
		options.Host,
		options.StartPort,
		options.EndPort,
		options.Workers,
	)

	portScanner, err := scanner.New(scanner.Config{
		Host:        options.Host,
		Workers:     options.Workers,
		StartPort:   options.StartPort,
		EndPort:     options.EndPort,
		DialTimeout: time.Second,
	})
	if err != nil {
		return fmt.Errorf("configure scanner: %w", err)
	}

	if portScanner.Workers() != options.Workers {
		logger.Debugf("Adjusted workers count to %d\n", portScanner.Workers())
	}

	startedAt := time.Now()
	logger.Debugf("Starting %d workers...\n", portScanner.Workers())
	logger.Debugf("Sending ports to workers...\n")

	for event := range portScanner.Scan(ctx) {
		switch event.Kind {
		case scanner.EventChecking:
			logger.Tracef("Checking port %d...\n", event.Port)
		case scanner.EventOpen:
			logger.Printf("TCP: %d\n", event.Port)
			logger.Debugf(
				"Connection established to port %d in %v\n",
				event.Port,
				event.Duration,
			)
			if event.Err != nil {
				logger.Debugf("Could not close connection to port %d: %v\n", event.Port, event.Err)
			}
		case scanner.EventClosed:
			logger.Tracef("Port %d is closed (%v)\n", event.Port, event.Err)
		}
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("scan interrupted: %w", err)
	}

	logger.Debugf("Finished sending ports\n")
	logger.Infof("Scan completed in %v\n", time.Since(startedAt))
	if err := logger.Err(); err != nil {
		return err
	}
	return nil
}
