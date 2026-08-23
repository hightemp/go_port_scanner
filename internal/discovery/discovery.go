// Package discovery filters unavailable hosts before a port scan starts.
package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// Strategy controls how target availability is checked.
type Strategy string

const (
	// StrategyNone considers every target reachable without probing it.
	StrategyNone Strategy = "none"
	// StrategyTCP checks whether any configured TCP port responds.
	StrategyTCP Strategy = "tcp"
	// StrategyICMP checks for an ICMP echo reply.
	StrategyICMP Strategy = "icmp"
	// StrategyICMPThenTCP tries ICMP first and falls back to TCP.
	StrategyICMPThenTCP Strategy = "icmp_then_tcp"
)

// Dialer establishes context-aware TCP connections.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Pinger performs an ICMP availability check.
type Pinger interface {
	Ping(ctx context.Context, target string, timeout time.Duration) (bool, error)
}

// EventKind identifies a diagnostic host discovery event.
type EventKind uint8

const (
	// EventResolution reports hostname resolution completion.
	EventResolution EventKind = iota
	// EventProbe reports one ICMP or TCP availability attempt.
	EventProbe
	// EventFallback reports a transition from ICMP to TCP.
	EventFallback
)

// Event describes a diagnostic event emitted during host discovery.
type Event struct {
	Kind      EventKind
	Target    string
	Method    Strategy
	Port      int
	Addresses []string
	Alive     bool
	Detail    string
	Duration  time.Duration
	Err       error
}

// Reporter receives discovery events and may be called concurrently.
type Reporter func(Event)

// Config defines a host discovery worker pool.
type Config struct {
	Strategy Strategy
	Ports    []int
	Workers  int
	Timeout  time.Duration
	Dialer   Dialer
	Pinger   Pinger
	Reporter Reporter
}

// Result describes the availability of one target.
type Result struct {
	Target string
	Alive  bool
	Method Strategy
	Err    error
}

// Discoverer checks target availability with bounded concurrency.
type Discoverer struct {
	strategy Strategy
	ports    []int
	workers  int
	timeout  time.Duration
	dialer   Dialer
	pinger   Pinger
	reporter Reporter
}

// New validates config and constructs a Discoverer.
func New(config Config) (*Discoverer, error) {
	switch config.Strategy {
	case StrategyNone, StrategyTCP, StrategyICMP, StrategyICMPThenTCP:
	default:
		return nil, fmt.Errorf("unsupported discovery strategy %q", config.Strategy)
	}
	if config.Workers < 1 {
		return nil, errors.New("workers must be greater than zero")
	}
	if config.Timeout <= 0 {
		return nil, errors.New("timeout must be greater than zero")
	}
	if (config.Strategy == StrategyTCP || config.Strategy == StrategyICMPThenTCP) && len(config.Ports) == 0 {
		return nil, errors.New("TCP discovery ports must not be empty")
	}
	for index, port := range config.Ports {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("ports[%d] must be between 1 and 65535", index)
		}
	}

	dialer := config.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	pinger := config.Pinger
	if pinger == nil {
		pinger = newICMPPinger(config.Reporter)
	}

	return &Discoverer{
		strategy: config.Strategy,
		ports:    append([]int(nil), config.Ports...),
		workers:  config.Workers,
		timeout:  config.Timeout,
		dialer:   dialer,
		pinger:   pinger,
		reporter: config.Reporter,
	}, nil
}

// Discover checks every target and returns results in the input order.
func (d *Discoverer) Discover(ctx context.Context, targets []string) ([]Result, error) {
	if len(targets) == 0 {
		return nil, errors.New("targets must not be empty")
	}

	type job struct {
		index  int
		target string
	}

	workerCount := min(d.workers, len(targets))
	jobs := make(chan job, workerCount)
	results := make([]Result, len(targets))
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for current := range jobs {
				results[current.index] = d.check(ctx, current.target)
			}
		}()
	}

sendJobs:
	for index, target := range targets {
		select {
		case jobs <- job{index: index, target: target}:
		case <-ctx.Done():
			break sendJobs
		}
	}
	close(jobs)
	workers.Wait()

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("discover hosts: %w", err)
	}
	return results, nil
}

func (d *Discoverer) check(ctx context.Context, target string) Result {
	result := Result{Target: target}
	switch d.strategy {
	case StrategyNone:
		result.Alive = true
		result.Method = StrategyNone
	case StrategyTCP:
		result.Alive, result.Err = d.checkTCP(ctx, target)
		if result.Alive {
			result.Method = StrategyTCP
		}
	case StrategyICMP:
		result.Alive, result.Err = d.checkICMP(ctx, target)
		if result.Alive {
			result.Method = StrategyICMP
		}
	case StrategyICMPThenTCP:
		result.Alive, result.Err = d.checkICMP(ctx, target)
		if result.Alive {
			result.Method = StrategyICMP
			return result
		}
		icmpError := result.Err
		if ctx.Err() != nil {
			result.Err = ctx.Err()
			return result
		}
		d.report(Event{
			Kind:   EventFallback,
			Target: target,
			Method: StrategyTCP,
			Detail: "ICMP did not confirm reachability",
			Err:    icmpError,
		})
		result.Alive, result.Err = d.checkTCP(ctx, target)
		if result.Alive {
			result.Method = StrategyTCP
			return result
		}
		result.Err = errors.Join(icmpError, result.Err)
	}
	return result
}

func (d *Discoverer) checkICMP(ctx context.Context, target string) (bool, error) {
	startedAt := time.Now()
	alive, err := d.pinger.Ping(ctx, target, d.timeout)
	detail := "no echo reply"
	if alive {
		detail = "echo reply"
	} else if err != nil {
		detail = "failed"
	}
	d.report(Event{
		Kind:     EventProbe,
		Target:   target,
		Method:   StrategyICMP,
		Alive:    alive,
		Detail:   detail,
		Duration: time.Since(startedAt),
		Err:      err,
	})
	return alive, err
}

func (d *Discoverer) checkTCP(ctx context.Context, target string) (bool, error) {
	var lastError error
	for _, port := range d.ports {
		startedAt := time.Now()
		attemptContext, cancel := context.WithTimeout(ctx, d.timeout)
		connection, err := d.dialer.DialContext(
			attemptContext,
			"tcp",
			net.JoinHostPort(target, strconv.Itoa(port)),
		)
		attemptError := attemptContext.Err()
		cancel()

		if err == nil {
			if closeErr := connection.Close(); closeErr != nil {
				d.report(Event{
					Kind:     EventProbe,
					Target:   target,
					Method:   StrategyTCP,
					Port:     port,
					Alive:    true,
					Detail:   "connected",
					Duration: time.Since(startedAt),
					Err:      closeErr,
				})
				return true, fmt.Errorf("close TCP discovery connection: %w", closeErr)
			}
			d.report(Event{
				Kind:     EventProbe,
				Target:   target,
				Method:   StrategyTCP,
				Port:     port,
				Alive:    true,
				Detail:   "connected",
				Duration: time.Since(startedAt),
			})
			return true, nil
		}
		if ctx.Err() != nil {
			d.report(Event{
				Kind:     EventProbe,
				Target:   target,
				Method:   StrategyTCP,
				Port:     port,
				Detail:   "canceled",
				Duration: time.Since(startedAt),
				Err:      ctx.Err(),
			})
			return false, ctx.Err()
		}
		if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) {
			d.report(Event{
				Kind:     EventProbe,
				Target:   target,
				Method:   StrategyTCP,
				Port:     port,
				Alive:    true,
				Detail:   "connection refused",
				Duration: time.Since(startedAt),
				Err:      err,
			})
			return true, nil
		}
		if errors.Is(attemptError, context.DeadlineExceeded) || isTimeout(err) {
			d.report(Event{
				Kind:     EventProbe,
				Target:   target,
				Method:   StrategyTCP,
				Port:     port,
				Detail:   "timeout",
				Duration: time.Since(startedAt),
			})
			continue
		}
		d.report(Event{
			Kind:     EventProbe,
			Target:   target,
			Method:   StrategyTCP,
			Port:     port,
			Detail:   "failed",
			Duration: time.Since(startedAt),
			Err:      err,
		})
		lastError = err
	}
	return false, lastError
}

func (d *Discoverer) report(event Event) {
	if d.reporter != nil {
		d.reporter(event)
	}
}

func isTimeout(err error) bool {
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}
