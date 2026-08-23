package main

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hightemp/go_port_scanner/internal/discovery"
	"github.com/hightemp/go_port_scanner/internal/logging"
)

func TestFilterDiscoveryResultsLogsUnavailableHosts(t *testing.T) {
	t.Parallel()

	probeError := errors.New("probe failed")
	results := []discovery.Result{
		{Target: "up", Alive: true, Method: discovery.StrategyTCP},
		{Target: "down"},
		{Target: "broken", Err: probeError},
	}
	var output bytes.Buffer
	targets, err := filterDiscoveryResults(logging.New(&output, logging.DebugLevel), results)
	if err != nil {
		t.Fatalf("filterDiscoveryResults() error = %v", err)
	}
	if !reflect.DeepEqual(targets, []string{"up"}) {
		t.Errorf("targets = %v, want [up]", targets)
	}
	for _, want := range []string{
		"Host up is reachable via tcp",
		"Host down is unavailable; skipping",
		"Host broken is unavailable; skipping (probe failed)",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("log output = %q, want it to contain %q", output.String(), want)
		}
	}
}

func TestFilterDiscoveryResultsRejectsAllUnavailable(t *testing.T) {
	t.Parallel()

	probeError := errors.New("ICMP unavailable")
	_, err := filterDiscoveryResults(
		logging.New(&bytes.Buffer{}, logging.InfoLevel),
		[]discovery.Result{{Target: "down", Err: probeError}},
	)
	if !errors.Is(err, probeError) {
		t.Fatalf("filterDiscoveryResults() error = %v, want wrapped probe error", err)
	}
}

func TestDiscoveryReporterLogging(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	reporter := newDiscoveryReporter(logging.New(&output, logging.DebugLevel))
	events := []discovery.Event{
		{Kind: discovery.EventResolution, Target: "host", Addresses: []string{"192.0.2.1"}, Duration: time.Millisecond},
		{Kind: discovery.EventResolution, Target: "bad", Err: errors.New("DNS failed")},
		{Kind: discovery.EventProbe, Target: "host", Method: discovery.StrategyICMP, Detail: "echo reply", Alive: true},
		{Kind: discovery.EventProbe, Target: "host", Method: discovery.StrategyICMP, Detail: "failed", Err: errors.New("socket failed")},
		{Kind: discovery.EventProbe, Target: "host", Method: discovery.StrategyTCP, Port: 443, Detail: "connected", Alive: true},
		{Kind: discovery.EventProbe, Target: "host", Method: discovery.StrategyTCP, Port: 80, Detail: "failed", Err: errors.New("route failed")},
		{Kind: discovery.EventFallback, Target: "host"},
		{Kind: discovery.EventFallback, Target: "bad", Err: errors.New("ICMP failed")},
	}
	for _, event := range events {
		reporter(event)
	}

	for _, want := range []string{
		"Resolved discovery target host to 192.0.2.1",
		"DNS resolution for discovery target bad failed",
		"ICMP discovery host: echo reply",
		"ICMP discovery host: failed",
		"TCP discovery host:443: connected",
		"TCP discovery host:80: failed",
		"returned no echo reply; falling back to TCP",
		"ICMP discovery for bad failed (ICMP failed); falling back to TCP",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("log output = %q, want it to contain %q", output.String(), want)
		}
	}
}
