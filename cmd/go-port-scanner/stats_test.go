package main

import (
	"bytes"
	"errors"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hightemp/go_port_scanner/internal/logging"
	"github.com/hightemp/go_port_scanner/internal/scanner"
)

func TestScanStatsObserve(t *testing.T) {
	t.Parallel()

	statistics := newScanStats(5)
	events := []scanner.Event{
		{Kind: scanner.EventChecking},
		{Kind: scanner.EventOpen},
		{Kind: scanner.EventClosed, Err: statsTimeoutError{}},
		{Kind: scanner.EventClosed, Err: syscall.ECONNREFUSED},
		{Kind: scanner.EventClosed, Err: syscall.EHOSTUNREACH},
		{Kind: scanner.EventClosed, Err: errors.New("TLS proxy failed")},
	}
	for _, event := range events {
		statistics.observe(event)
	}

	if statistics.completed != 5 || statistics.open != 1 || statistics.closed != 4 ||
		statistics.timeouts != 1 || statistics.refused != 1 || statistics.unreachable != 1 ||
		statistics.otherErrors != 1 {
		t.Errorf("scanStats = %#v", statistics)
	}
}

func TestScanStatsLogging(t *testing.T) {
	t.Parallel()

	statistics := scanStats{
		total:     100,
		completed: 50,
		open:      2,
		closed:    48,
		timeouts:  10,
		refused:   38,
	}
	var output bytes.Buffer
	logger := logging.New(&output, logging.InfoLevel)
	statistics.logProgress(logger, 2*time.Second)
	statistics.logSummary(logger, 2*time.Second)

	for _, want := range []string{
		"Progress: 50.0% (50/100), open=2, rate=25 checks/s, ETA=2s",
		"Scan summary: completed=50/100, open=2, closed=48, timeouts=10, refused=38",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("log output = %q, want it to contain %q", output.String(), want)
		}
	}
}

func TestScanStatsCompletedProgress(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	logger := logging.New(&output, logging.InfoLevel)
	scanStats{total: 0}.logProgress(logger, 0)
	if !strings.Contains(output.String(), "100.0% (0/0)") || !strings.Contains(output.String(), "ETA=0s") {
		t.Errorf("progress output = %q", output.String())
	}
}

type statsTimeoutError struct{}

func (statsTimeoutError) Error() string   { return "timeout" }
func (statsTimeoutError) Timeout() bool   { return true }
func (statsTimeoutError) Temporary() bool { return true }
