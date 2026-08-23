package reversedns

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestNewValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config Config
	}{
		{name: "zero workers", config: Config{Timeout: time.Second}},
		{name: "zero timeout", config: Config{Workers: 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := New(tt.config); err == nil {
				t.Fatal("New() error = nil, want validation error")
			}
		})
	}
}

func TestResolve(t *testing.T) {
	t.Parallel()

	lookup, err := New(Config{
		Workers: 2,
		Timeout: time.Second,
		Resolver: fakeResolver{responses: map[string]fakeResponse{
			"192.0.2.10":  {names: []string{"host.example.", "alias.example."}},
			"2001:db8::1": {err: errors.New("not found")},
			"192.0.2.11":  {names: []string{" ", "."}},
		}},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	results, err := lookup.Resolve(context.Background(), []string{
		"192.0.2.10",
		"example.com",
		"2001:db8::1",
		"192.0.2.11",
	})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("Resolve() result count = %d, want 3", len(results))
	}
	if results[0].Target != "192.0.2.10" || results[0].Hostname != "host.example" || results[0].Err != nil {
		t.Errorf("first result = %#v", results[0])
	}
	if results[1].Target != "2001:db8::1" || results[1].Err == nil ||
		results[2].Target != "192.0.2.11" || !errors.Is(results[2].Err, ErrNoHostname) {
		t.Errorf("failure results = %#v", results[1:])
	}
}

func TestResolveTimeoutAndCancellation(t *testing.T) {
	t.Parallel()

	lookup, err := New(Config{Workers: 1, Timeout: 10 * time.Millisecond, Resolver: blockingResolver{}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	results, err := lookup.Resolve(context.Background(), []string{"192.0.2.1"})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if len(results) != 1 || !errors.Is(results[0].Err, context.DeadlineExceeded) {
		t.Errorf("Resolve() results = %#v, want per-lookup deadline", results)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results, err = lookup.Resolve(ctx, []string{"192.0.2.1"})
	if !errors.Is(err, context.Canceled) || results != nil {
		t.Errorf("Resolve(cancelled) = %#v, %v; want nil, context.Canceled", results, err)
	}
}

func TestResolveBoundsConcurrencyAndSkipsHostnames(t *testing.T) {
	t.Parallel()

	resolver := &concurrencyResolver{release: make(chan struct{})}
	lookup, err := New(Config{Workers: 2, Timeout: time.Second, Resolver: resolver})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	done := make(chan []Result, 1)
	go func() {
		results, resolveErr := lookup.Resolve(context.Background(), []string{
			"192.0.2.1", "host.example", "192.0.2.2", "192.0.2.3",
		})
		if resolveErr != nil {
			done <- nil
			return
		}
		done <- results
	}()

	deadline := time.After(time.Second)
	for resolver.maximum() < 2 {
		select {
		case <-deadline:
			t.Fatal("two lookup workers did not become active")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if resolver.maximum() != 2 {
		t.Fatalf("maximum concurrency = %d, want 2", resolver.maximum())
	}
	close(resolver.release)
	results := <-done
	if got := []string{results[0].Target, results[1].Target, results[2].Target}; !reflect.DeepEqual(got, []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}) {
		t.Errorf("result order = %v", got)
	}
}

type fakeResponse struct {
	names []string
	err   error
}

type fakeResolver struct {
	responses map[string]fakeResponse
}

func (resolver fakeResolver) LookupAddr(_ context.Context, address string) ([]string, error) {
	response := resolver.responses[address]
	return response.names, response.err
}

type blockingResolver struct{}

func (blockingResolver) LookupAddr(ctx context.Context, _ string) ([]string, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

type concurrencyResolver struct {
	mu      sync.Mutex
	active  int
	maxSeen int
	release chan struct{}
}

func (resolver *concurrencyResolver) LookupAddr(_ context.Context, address string) ([]string, error) {
	resolver.mu.Lock()
	resolver.active++
	resolver.maxSeen = max(resolver.maxSeen, resolver.active)
	resolver.mu.Unlock()

	<-resolver.release

	resolver.mu.Lock()
	resolver.active--
	resolver.mu.Unlock()
	return []string{address + ".example."}, nil
}

func (resolver *concurrencyResolver) maximum() int {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	return resolver.maxSeen
}
