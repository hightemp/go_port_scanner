package main

import (
	"context"
	"fmt"
	"time"

	appconfig "github.com/hightemp/go_port_scanner/internal/config"
	"github.com/hightemp/go_port_scanner/internal/logging"
	"github.com/hightemp/go_port_scanner/internal/reversedns"
)

func resolveHostnames(
	ctx context.Context,
	logger *logging.Logger,
	targets []string,
	settings appconfig.ReverseDNS,
	resolver reversedns.AddressResolver,
) (map[string]string, error) {
	lookup, err := reversedns.New(reversedns.Config{
		Workers:  settings.Workers,
		Timeout:  settings.Timeout.Duration,
		Resolver: resolver,
	})
	if err != nil {
		return nil, fmt.Errorf("configure reverse DNS: %w", err)
	}

	startedAt := time.Now()
	logger.Infof(
		"Resolving reverse DNS names with %d workers and %v timeout\n",
		settings.Workers,
		settings.Timeout.Duration,
	)
	results, err := lookup.Resolve(ctx, targets)
	if err != nil {
		return nil, fmt.Errorf("resolve reverse DNS names: %w", err)
	}

	hostnames := make(map[string]string, len(results))
	for _, result := range results {
		if result.Err != nil {
			logger.Debugf("Reverse DNS lookup for %s failed: %v\n", result.Target, result.Err)
			continue
		}
		hostnames[result.Target] = result.Hostname
		logger.Debugf("Reverse DNS resolved %s to %s\n", result.Target, result.Hostname)
	}
	logger.Infof(
		"Reverse DNS completed in %v: %d/%d IP target(s) resolved\n",
		time.Since(startedAt),
		len(hostnames),
		len(results),
	)
	return hostnames, nil
}
