// Package reversedns resolves optional PTR names for IP scan targets.
package reversedns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// ErrNoHostname indicates that a successful lookup returned no usable names.
var ErrNoHostname = errors.New("reverse DNS lookup returned no hostname")

// AddressResolver is implemented by net.Resolver and test resolvers.
type AddressResolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// Config controls reverse DNS concurrency and per-address timeout.
type Config struct {
	Workers  int
	Timeout  time.Duration
	Resolver AddressResolver
}

// Result contains the first PTR hostname returned for one IP target.
type Result struct {
	Target   string
	Hostname string
	Err      error
}

// Lookup performs bounded concurrent PTR lookups.
type Lookup struct {
	workers  int
	timeout  time.Duration
	resolver AddressResolver
}

// New validates config and constructs a reverse DNS lookup pool.
func New(config Config) (*Lookup, error) {
	if config.Workers < 1 {
		return nil, errors.New("workers must be greater than zero")
	}
	if config.Timeout <= 0 {
		return nil, errors.New("timeout must be greater than zero")
	}
	resolver := config.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return &Lookup{workers: config.Workers, timeout: config.Timeout, resolver: resolver}, nil
}

// Resolve looks up only IP literals, preserves their input order, and records
// individual DNS failures in Result.Err. Hostname targets are intentionally
// skipped because they already have a user-provided name.
func (lookup *Lookup) Resolve(ctx context.Context, targets []string) ([]Result, error) {
	type job struct {
		index   int
		target  string
		address string
	}
	type indexedResult struct {
		index  int
		result Result
	}

	jobs := make([]job, 0, len(targets))
	for _, target := range targets {
		address, err := netip.ParseAddr(target)
		if err != nil {
			continue
		}
		jobs = append(jobs, job{index: len(jobs), target: target, address: address.String()})
	}
	if len(jobs) == 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, nil
	}

	workerCount := min(lookup.workers, len(jobs))
	jobQueue := make(chan job, len(jobs))
	resultQueue := make(chan indexedResult, len(jobs))
	for _, item := range jobs {
		jobQueue <- item
	}
	close(jobQueue)

	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case item, open := <-jobQueue:
					if !open {
						return
					}
					resultQueue <- indexedResult{index: item.index, result: lookup.resolveOne(ctx, item.target, item.address)}
				}
			}
		}()
	}
	workers.Wait()
	close(resultQueue)

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	results := make([]Result, len(jobs))
	for result := range resultQueue {
		results[result.index] = result.result
	}
	return results, nil
}

func (lookup *Lookup) resolveOne(ctx context.Context, target, address string) Result {
	lookupContext, cancel := context.WithTimeout(ctx, lookup.timeout)
	defer cancel()

	names, err := lookup.resolver.LookupAddr(lookupContext, address)
	if err != nil {
		return Result{Target: target, Err: fmt.Errorf("lookup PTR: %w", err)}
	}
	for _, name := range names {
		hostname := strings.TrimSuffix(strings.TrimSpace(name), ".")
		if hostname != "" {
			hostname = strings.ReplaceAll(hostname, "\r", "\\r")
			hostname = strings.ReplaceAll(hostname, "\n", "\\n")
			return Result{Target: target, Hostname: hostname}
		}
	}
	return Result{Target: target, Err: ErrNoHostname}
}
