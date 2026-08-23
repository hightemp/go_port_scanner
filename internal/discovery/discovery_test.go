package discovery

import (
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestNewValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config Config
	}{
		{name: "unknown strategy", config: Config{Strategy: "unknown", Workers: 1, Timeout: time.Second}},
		{name: "zero workers", config: Config{Strategy: StrategyNone, Timeout: time.Second}},
		{name: "zero timeout", config: Config{Strategy: StrategyNone, Workers: 1}},
		{name: "TCP without ports", config: Config{Strategy: StrategyTCP, Workers: 1, Timeout: time.Second}},
		{name: "combined without ports", config: Config{Strategy: StrategyICMPThenTCP, Workers: 1, Timeout: time.Second}},
		{name: "invalid port", config: Config{Strategy: StrategyTCP, Ports: []int{0}, Workers: 1, Timeout: time.Second}},
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

func TestDiscoverStrategies(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		strategy   Strategy
		targets    []string
		ports      []int
		dialErrors map[string]error
		ping       map[string]pingResult
		want       []Result
	}{
		{
			name:     "none preserves every target",
			strategy: StrategyNone,
			targets:  []string{"first", "second"},
			want: []Result{
				{Target: "first", Alive: true, Method: StrategyNone},
				{Target: "second", Alive: true, Method: StrategyNone},
			},
		},
		{
			name:     "TCP accepts connected and refused hosts",
			strategy: StrategyTCP,
			targets:  []string{"connected", "refused", "down"},
			ports:    []int{22, 80},
			dialErrors: map[string]error{
				"connected:22": nil,
				"refused:22":   syscall.ECONNREFUSED,
				"down:22":      testTimeoutError{},
				"down:80":      testTimeoutError{},
			},
			want: []Result{
				{Target: "connected", Alive: true, Method: StrategyTCP},
				{Target: "refused", Alive: true, Method: StrategyTCP},
				{Target: "down"},
			},
		},
		{
			name:     "ICMP uses echo result",
			strategy: StrategyICMP,
			targets:  []string{"up", "down"},
			ping: map[string]pingResult{
				"up":   {alive: true},
				"down": {},
			},
			want: []Result{
				{Target: "up", Alive: true, Method: StrategyICMP},
				{Target: "down"},
			},
		},
		{
			name:     "combined falls back to TCP",
			strategy: StrategyICMPThenTCP,
			targets:  []string{"icmp-up", "tcp-up", "down"},
			ports:    []int{443},
			ping: map[string]pingResult{
				"icmp-up": {alive: true},
				"tcp-up":  {err: errors.New("ICMP unavailable")},
				"down":    {},
			},
			dialErrors: map[string]error{
				"tcp-up:443": nil,
				"down:443":   testTimeoutError{},
			},
			want: []Result{
				{Target: "icmp-up", Alive: true, Method: StrategyICMP},
				{Target: "tcp-up", Alive: true, Method: StrategyTCP},
				{Target: "down"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dialer := &fakeDialer{errors: tt.dialErrors}
			pinger := &fakePinger{results: tt.ping}
			discoverer, err := New(Config{
				Strategy: tt.strategy,
				Ports:    tt.ports,
				Workers:  2,
				Timeout:  10 * time.Millisecond,
				Dialer:   dialer,
				Pinger:   pinger,
			})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			got, err := discoverer.Discover(context.Background(), tt.targets)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Discover() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestDiscoverReportsProbeAndCloseErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		strategy    Strategy
		dialer      Dialer
		pinger      Pinger
		wantAlive   bool
		wantMessage string
	}{
		{
			name:        "TCP error",
			strategy:    StrategyTCP,
			dialer:      &fakeDialer{errors: map[string]error{"host:80": errors.New("route failed")}},
			pinger:      &fakePinger{},
			wantMessage: "route failed",
		},
		{
			name:        "ICMP error",
			strategy:    StrategyICMP,
			dialer:      &fakeDialer{},
			pinger:      &fakePinger{results: map[string]pingResult{"host": {err: errors.New("socket failed")}}},
			wantMessage: "socket failed",
		},
		{
			name:        "connection close error",
			strategy:    StrategyTCP,
			dialer:      closeErrorDialer{},
			pinger:      &fakePinger{},
			wantAlive:   true,
			wantMessage: "close TCP discovery connection",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			discoverer, err := New(Config{
				Strategy: tt.strategy,
				Ports:    []int{80},
				Workers:  1,
				Timeout:  time.Second,
				Dialer:   tt.dialer,
				Pinger:   tt.pinger,
			})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			results, err := discoverer.Discover(context.Background(), []string{"host"})
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if results[0].Alive != tt.wantAlive || results[0].Err == nil ||
				!strings.Contains(results[0].Err.Error(), tt.wantMessage) {
				t.Fatalf("Discover() result = %#v, want alive=%v and error containing %q", results[0], tt.wantAlive, tt.wantMessage)
			}
		})
	}
}

func TestDiscoverCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	discoverer, err := New(Config{
		Strategy: StrategyICMP,
		Workers:  2,
		Timeout:  time.Second,
		Pinger:   &fakePinger{},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := discoverer.Discover(ctx, []string{"one", "two"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Discover() error = %v, want context.Canceled", err)
	}
}

func TestDiscoverRejectsEmptyTargets(t *testing.T) {
	t.Parallel()

	discoverer, err := New(Config{Strategy: StrategyNone, Workers: 1, Timeout: time.Second})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := discoverer.Discover(context.Background(), nil); err == nil {
		t.Fatal("Discover() error = nil, want empty targets error")
	}
}

type pingResult struct {
	alive bool
	err   error
}

type fakePinger struct {
	mu      sync.Mutex
	results map[string]pingResult
	calls   []string
}

func (p *fakePinger) Ping(_ context.Context, target string, _ time.Duration) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, target)
	result := p.results[target]
	return result.alive, result.err
}

type fakeDialer struct {
	mu     sync.Mutex
	errors map[string]error
	calls  []string
}

func (d *fakeDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, address)
	err, exists := d.errors[address]
	if !exists {
		return nil, errors.New("unexpected address")
	}
	if err != nil {
		return nil, err
	}
	return stubConnection{}, nil
}

type closeErrorDialer struct{}

func (closeErrorDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return stubConnection{closeErr: errors.New("close failed")}, nil
}

type stubConnection struct {
	closeErr error
}

func (c stubConnection) Read([]byte) (int, error)         { return 0, io.EOF }
func (c stubConnection) Write(buffer []byte) (int, error) { return len(buffer), nil }
func (c stubConnection) Close() error                     { return c.closeErr }
func (stubConnection) LocalAddr() net.Addr                { return stubAddress("local") }
func (stubConnection) RemoteAddr() net.Addr               { return stubAddress("remote") }
func (stubConnection) SetDeadline(time.Time) error        { return nil }
func (stubConnection) SetReadDeadline(time.Time) error    { return nil }
func (stubConnection) SetWriteDeadline(time.Time) error   { return nil }

type stubAddress string

func (a stubAddress) Network() string { return "test" }
func (a stubAddress) String() string  { return string(a) }

type testTimeoutError struct{}

func (testTimeoutError) Error() string   { return "timeout" }
func (testTimeoutError) Timeout() bool   { return true }
func (testTimeoutError) Temporary() bool { return true }
