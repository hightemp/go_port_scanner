// Package scanner performs concurrent TCP port scans.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/hightemp/go_port_scanner/internal/probe"
)

const maxPort = 65535

type target struct {
	host string
	port int
}

// Dialer establishes context-aware TCP connections.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// EventKind describes a state observed while checking a port.
type EventKind uint8

const (
	// EventChecking is emitted immediately before a connection attempt.
	EventChecking EventKind = iota
	// EventOpen reports a successful TCP connection.
	EventOpen
	// EventClosed reports a failed TCP connection.
	EventClosed
)

// Event describes one observable step of a port scan.
type Event struct {
	Kind     EventKind
	Host     string
	Port     int
	Duration time.Duration
	Probes   []probe.Result
	Err      error
}

// Config defines the target, range, concurrency, and timeout for a scan.
type Config struct {
	Targets     []string
	Ports       []int
	Workers     int
	DialTimeout time.Duration
	Dialer      Dialer
	Probes      *probe.Registry
}

// Scanner checks a configured TCP port range concurrently.
type Scanner struct {
	config Config
}

// New validates config and constructs a Scanner.
func New(config Config) (*Scanner, error) {
	if len(config.Targets) == 0 {
		return nil, errors.New("targets must not be empty")
	}
	for index, host := range config.Targets {
		if host == "" {
			return nil, fmt.Errorf("targets[%d] must not be empty", index)
		}
	}
	if len(config.Ports) == 0 {
		return nil, errors.New("ports must not be empty")
	}
	for index, port := range config.Ports {
		if port < 1 || port > maxPort {
			return nil, fmt.Errorf("ports[%d] must be between 1 and %d", index, maxPort)
		}
	}
	if config.Workers < 1 {
		return nil, errors.New("workers must be greater than zero")
	}
	if config.DialTimeout <= 0 {
		return nil, errors.New("dial timeout must be greater than zero")
	}

	checkCount := len(config.Targets) * len(config.Ports)
	if config.Workers > checkCount {
		config.Workers = checkCount
	}
	config.Targets = append([]string(nil), config.Targets...)
	config.Ports = append([]int(nil), config.Ports...)

	return &Scanner{config: config}, nil
}

// Workers returns the effective number of workers after range adjustment.
func (s *Scanner) Workers() int {
	return s.config.Workers
}

// Checks returns the total number of target and port combinations.
func (s *Scanner) Checks() int {
	return len(s.config.Targets) * len(s.config.Ports)
}

// Scan starts the worker pool and returns its event stream.
// The channel is closed after every worker exits or ctx is cancelled.
func (s *Scanner) Scan(ctx context.Context) <-chan Event {
	events := make(chan Event, s.config.Workers)
	targets := make(chan target, s.config.Workers)

	go func() {
		var workers sync.WaitGroup
		workers.Add(s.config.Workers)

		for range s.config.Workers {
			go func() {
				defer workers.Done()
				s.worker(ctx, targets, events)
			}()
		}

		s.sendTargets(ctx, targets)
		workers.Wait()
		close(events)
	}()

	return events
}

func (s *Scanner) sendTargets(ctx context.Context, targets chan<- target) {
	defer close(targets)

	for _, host := range s.config.Targets {
		for _, port := range s.config.Ports {
			select {
			case targets <- target{host: host, port: port}:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (s *Scanner) worker(ctx context.Context, targets <-chan target, events chan<- Event) {
	var dialer Dialer = &net.Dialer{Timeout: s.config.DialTimeout}
	if s.config.Dialer != nil {
		dialer = s.config.Dialer
	}

	for {
		select {
		case <-ctx.Done():
			return
		case current, ok := <-targets:
			if !ok {
				return
			}
			if !emit(ctx, events, Event{
				Kind: EventChecking,
				Host: current.host,
				Port: current.port,
			}) {
				return
			}

			startedAt := time.Now()
			address := net.JoinHostPort(current.host, strconv.Itoa(current.port))
			connection, err := dialer.DialContext(ctx, "tcp", address)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				if !emit(ctx, events, Event{
					Kind: EventClosed,
					Host: current.host,
					Port: current.port,
					Err:  err,
				}) {
					return
				}
				continue
			}

			event := Event{
				Kind:     EventOpen,
				Host:     current.host,
				Port:     current.port,
				Duration: time.Since(startedAt),
			}
			protocols := s.config.Probes.ForPort(current.port)
			if len(protocols) == 0 {
				if err := connection.Close(); err != nil {
					event.Err = fmt.Errorf("close connection: %w", err)
				}
			} else {
				event.Probes, event.Err = s.runProbes(
					ctx,
					dialer,
					address,
					current,
					connection,
					protocols,
				)
				if ctx.Err() != nil {
					return
				}
			}
			if !emit(ctx, events, event) {
				return
			}
		}
	}
}

func (s *Scanner) runProbes(
	ctx context.Context,
	dialer Dialer,
	address string,
	target target,
	firstConnection net.Conn,
	protocols []probe.Prober,
) ([]probe.Result, error) {
	results := make([]probe.Result, 0, len(protocols))
	var closeErrors error

	for index, protocol := range protocols {
		connection := firstConnection
		if index > 0 {
			startedAt := time.Now()
			var err error
			connection, err = dialer.DialContext(ctx, "tcp", address)
			if err != nil {
				if ctx.Err() != nil {
					return results, closeErrors
				}
				results = append(results, probe.Result{
					Protocol: protocol.Name(),
					Duration: time.Since(startedAt),
					Err:      fmt.Errorf("connect for protocol probe: %w", err),
				})
				continue
			}
		}

		result := s.config.Probes.Run(ctx, protocol, connection, probe.Target{
			Host: target.host,
			Port: target.port,
		})
		results = append(results, result)
		if err := connection.Close(); err != nil {
			closeErrors = errors.Join(closeErrors, fmt.Errorf("close %s probe connection: %w", protocol.Name(), err))
		}
	}
	return results, closeErrors
}

func emit(ctx context.Context, events chan<- Event, event Event) bool {
	select {
	case events <- event:
		return true
	case <-ctx.Done():
		return false
	}
}
