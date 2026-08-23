package main

import (
	"errors"
	"net"
	"syscall"
	"time"

	"github.com/hightemp/go_port_scanner/internal/logging"
	"github.com/hightemp/go_port_scanner/internal/scanner"
)

type scanStats struct {
	total       int
	completed   int
	open        int
	closed      int
	timeouts    int
	refused     int
	unreachable int
	otherErrors int
}

func newScanStats(total int) scanStats {
	return scanStats{total: total}
}

func (s *scanStats) observe(event scanner.Event) {
	switch event.Kind {
	case scanner.EventOpen:
		s.completed++
		s.open++
	case scanner.EventClosed:
		s.completed++
		s.closed++
		switch {
		case networkTimeout(event.Err):
			s.timeouts++
		case errors.Is(event.Err, syscall.ECONNREFUSED), errors.Is(event.Err, syscall.ECONNRESET):
			s.refused++
		case errors.Is(event.Err, syscall.EHOSTUNREACH), errors.Is(event.Err, syscall.ENETUNREACH):
			s.unreachable++
		default:
			s.otherErrors++
		}
	}
}

func (s scanStats) logProgress(logger *logging.Logger, elapsed time.Duration) {
	percentage := 100.0
	if s.total > 0 {
		percentage = float64(s.completed) * 100 / float64(s.total)
	}
	rate := 0.0
	if elapsed > 0 {
		rate = float64(s.completed) / elapsed.Seconds()
	}
	eta := "unknown"
	if rate > 0 && s.completed < s.total {
		remaining := float64(s.total-s.completed) / rate
		eta = time.Duration(remaining * float64(time.Second)).Round(time.Second).String()
	} else if s.completed >= s.total {
		eta = "0s"
	}

	logger.Infof(
		"Progress: %.1f%% (%d/%d), open=%d, rate=%.0f checks/s, ETA=%s\n",
		percentage,
		s.completed,
		s.total,
		s.open,
		rate,
		eta,
	)
}

func (s scanStats) logSummary(logger *logging.Logger, elapsed time.Duration) {
	logger.Infof(
		"Scan summary: completed=%d/%d, open=%d, closed=%d, timeouts=%d, refused=%d, unreachable=%d, other_errors=%d, duration=%v\n",
		s.completed,
		s.total,
		s.open,
		s.closed,
		s.timeouts,
		s.refused,
		s.unreachable,
		s.otherErrors,
		elapsed,
	)
}

func networkTimeout(err error) bool {
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}
