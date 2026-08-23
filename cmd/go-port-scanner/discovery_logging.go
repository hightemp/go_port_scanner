package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/hightemp/go_port_scanner/internal/discovery"
	"github.com/hightemp/go_port_scanner/internal/logging"
)

func filterDiscoveryResults(logger *logging.Logger, results []discovery.Result) ([]string, error) {
	reachableTargets := make([]string, 0, len(results))
	var firstDiscoveryError error
	for _, result := range results {
		if result.Alive {
			reachableTargets = append(reachableTargets, result.Target)
			logger.Debugf("Host %s is reachable via %s\n", result.Target, result.Method)
			if result.Err != nil {
				logger.Debugf("Host discovery cleanup for %s failed: %v\n", result.Target, result.Err)
			}
			continue
		}
		if result.Err != nil {
			if firstDiscoveryError == nil {
				firstDiscoveryError = result.Err
			}
			logger.Infof("Host %s is unavailable; skipping (%v)\n", result.Target, result.Err)
			continue
		}
		logger.Infof("Host %s is unavailable; skipping\n", result.Target)
	}
	if len(reachableTargets) > 0 {
		return reachableTargets, nil
	}
	if firstDiscoveryError != nil {
		return nil, fmt.Errorf("host discovery found no reachable targets: %w", firstDiscoveryError)
	}
	return nil, errors.New("host discovery found no reachable targets")
}

func newDiscoveryReporter(logger *logging.Logger) discovery.Reporter {
	return func(event discovery.Event) {
		switch event.Kind {
		case discovery.EventResolution:
			if event.Err != nil {
				logger.Debugf(
					"DNS resolution for discovery target %s failed in %v: %v\n",
					event.Target,
					event.Duration,
					event.Err,
				)
				return
			}
			logger.Debugf(
				"Resolved discovery target %s to %s in %v\n",
				event.Target,
				strings.Join(event.Addresses, ", "),
				event.Duration,
			)
		case discovery.EventProbe:
			logDiscoveryProbe(logger, event)
		case discovery.EventFallback:
			if event.Err != nil {
				logger.Debugf(
					"ICMP discovery for %s failed (%v); falling back to TCP\n",
					event.Target,
					event.Err,
				)
				return
			}
			logger.Debugf(
				"ICMP discovery for %s returned no echo reply; falling back to TCP\n",
				event.Target,
			)
		}
	}
}

func logDiscoveryProbe(logger *logging.Logger, event discovery.Event) {
	if event.Method == discovery.StrategyTCP {
		if event.Err != nil {
			logger.Debugf(
				"TCP discovery %s:%d: %s in %v (%v)\n",
				event.Target,
				event.Port,
				event.Detail,
				event.Duration,
				event.Err,
			)
			return
		}
		logger.Debugf(
			"TCP discovery %s:%d: %s in %v\n",
			event.Target,
			event.Port,
			event.Detail,
			event.Duration,
		)
		return
	}

	if event.Err != nil {
		logger.Debugf(
			"ICMP discovery %s: %s in %v (%v)\n",
			event.Target,
			event.Detail,
			event.Duration,
			event.Err,
		)
		return
	}
	logger.Debugf(
		"ICMP discovery %s: %s in %v\n",
		event.Target,
		event.Detail,
		event.Duration,
	)
}
