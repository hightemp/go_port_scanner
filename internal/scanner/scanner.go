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
)

const maxPort = 65535

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
	Port     int
	Duration time.Duration
	Err      error
}

// Config defines the target, range, concurrency, and timeout for a scan.
type Config struct {
	Host        string
	Workers     int
	StartPort   int
	EndPort     int
	DialTimeout time.Duration
}

// Scanner checks a configured TCP port range concurrently.
type Scanner struct {
	config Config
}

// New validates config and constructs a Scanner.
func New(config Config) (*Scanner, error) {
	if config.Host == "" {
		return nil, errors.New("host must not be empty")
	}
	if config.StartPort < 1 || config.StartPort > maxPort {
		return nil, fmt.Errorf("start port must be between 1 and %d", maxPort)
	}
	if config.EndPort < 1 || config.EndPort > maxPort {
		return nil, fmt.Errorf("end port must be between 1 and %d", maxPort)
	}
	if config.StartPort > config.EndPort {
		return nil, errors.New("start port must not be greater than end port")
	}
	if config.Workers < 1 {
		return nil, errors.New("workers must be greater than zero")
	}
	if config.DialTimeout <= 0 {
		return nil, errors.New("dial timeout must be greater than zero")
	}

	portCount := config.EndPort - config.StartPort + 1
	if config.Workers > portCount {
		config.Workers = portCount
	}

	return &Scanner{config: config}, nil
}

// Workers returns the effective number of workers after range adjustment.
func (s *Scanner) Workers() int {
	return s.config.Workers
}

// Scan starts the worker pool and returns its event stream.
// The channel is closed after every worker exits or ctx is cancelled.
func (s *Scanner) Scan(ctx context.Context) <-chan Event {
	events := make(chan Event, s.config.Workers)
	ports := make(chan int, s.config.Workers)

	go func() {
		var workers sync.WaitGroup
		workers.Add(s.config.Workers)

		for range s.config.Workers {
			go func() {
				defer workers.Done()
				s.worker(ctx, ports, events)
			}()
		}

		s.sendPorts(ctx, ports)
		workers.Wait()
		close(events)
	}()

	return events
}

func (s *Scanner) sendPorts(ctx context.Context, ports chan<- int) {
	defer close(ports)

	for port := s.config.StartPort; port <= s.config.EndPort; port++ {
		select {
		case ports <- port:
		case <-ctx.Done():
			return
		}
	}
}

func (s *Scanner) worker(ctx context.Context, ports <-chan int, events chan<- Event) {
	dialer := net.Dialer{Timeout: s.config.DialTimeout}

	for {
		select {
		case <-ctx.Done():
			return
		case port, ok := <-ports:
			if !ok {
				return
			}
			if !emit(ctx, events, Event{Kind: EventChecking, Port: port}) {
				return
			}

			startedAt := time.Now()
			address := net.JoinHostPort(s.config.Host, strconv.Itoa(port))
			connection, err := dialer.DialContext(ctx, "tcp", address)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				if !emit(ctx, events, Event{Kind: EventClosed, Port: port, Err: err}) {
					return
				}
				continue
			}

			event := Event{
				Kind:     EventOpen,
				Port:     port,
				Duration: time.Since(startedAt),
			}
			if err := connection.Close(); err != nil {
				event.Err = fmt.Errorf("close connection: %w", err)
			}
			if !emit(ctx, events, event) {
				return
			}
		}
	}
}

func emit(ctx context.Context, events chan<- Event, event Event) bool {
	select {
	case events <- event:
		return true
	case <-ctx.Done():
		return false
	}
}
