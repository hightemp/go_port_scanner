package scanner

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/hightemp/go_port_scanner/internal/probe"
)

func TestNewValidation(t *testing.T) {
	t.Parallel()

	valid := Config{
		Targets:     []string{"localhost"},
		Ports:       []int{1},
		Workers:     1,
		DialTimeout: time.Second,
	}

	tests := []struct {
		name   string
		change func(*Config)
	}{
		{name: "empty targets", change: func(config *Config) { config.Targets = nil }},
		{name: "empty host", change: func(config *Config) { config.Targets = []string{""} }},
		{name: "empty ports", change: func(config *Config) { config.Ports = nil }},
		{name: "port below range", change: func(config *Config) { config.Ports = []int{0} }},
		{name: "port above range", change: func(config *Config) { config.Ports = []int{maxPort + 1} }},
		{name: "zero workers", change: func(config *Config) { config.Workers = 0 }},
		{name: "zero timeout", change: func(config *Config) { config.DialTimeout = 0 }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			config := valid
			tt.change(&config)
			if _, err := New(config); err == nil {
				t.Fatal("New() error = nil, want validation error")
			}
		})
	}
}

func TestNewAdjustsWorkerCount(t *testing.T) {
	t.Parallel()

	portScanner, err := New(Config{
		Targets:     []string{"host-a", "host-b"},
		Ports:       []int{80, 81},
		Workers:     100,
		DialTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got, want := portScanner.Workers(), 4; got != want {
		t.Errorf("Workers() = %d, want %d", got, want)
	}
	if got, want := portScanner.Checks(), 4; got != want {
		t.Errorf("Checks() = %d, want %d", got, want)
	}
}

func TestScanFindsOpenPort(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			t.Errorf("listener.Close() error = %v", err)
		}
	}()

	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("net.SplitHostPort() error = %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("strconv.Atoi() error = %v", err)
	}

	portScanner, err := New(Config{
		Targets:     []string{"127.0.0.1"},
		Ports:       []int{port},
		Workers:     1,
		DialTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	var events []Event
	for event := range portScanner.Scan(context.Background()) {
		events = append(events, event)
	}

	if len(events) != 2 || events[0].Kind != EventChecking || events[1].Kind != EventOpen {
		t.Fatalf("Scan() events = %v, want checking and open", events)
	}
	for _, event := range events {
		if event.Host != "127.0.0.1" || event.Port != port {
			t.Errorf("Scan() event target = %s:%d, want 127.0.0.1:%d", event.Host, event.Port, port)
		}
	}
}

func TestScanUsesConfiguredDialer(t *testing.T) {
	t.Parallel()

	dialer := &recordingDialer{addresses: make(chan string, 1)}
	portScanner, err := New(Config{
		Targets:     []string{"example.com"},
		Ports:       []int{443},
		Workers:     1,
		DialTimeout: time.Second,
		Dialer:      dialer,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	var sawOpen bool
	for event := range portScanner.Scan(context.Background()) {
		if event.Kind == EventOpen {
			sawOpen = true
		}
	}
	if !sawOpen {
		t.Fatal("Scan() did not emit an open event")
	}
	if got := <-dialer.addresses; got != "example.com:443" {
		t.Errorf("DialContext() address = %q, want example.com:443", got)
	}
}

func TestScanRunsEveryProbeWithANewConnection(t *testing.T) {
	t.Parallel()

	registry, err := probe.NewRegistry(probe.Config{
		Timeout: time.Second,
		Definitions: []probe.Definition{
			{Name: "ssh", Ports: []int{1234}},
			{Name: "ftp", Ports: []int{1234}},
		},
	})
	if err != nil {
		t.Fatalf("probe.NewRegistry() error = %v", err)
	}
	dialer := &sequenceDialer{responses: []string{
		"SSH-2.0-test\r\n",
		"220 FTP ready\r\n",
	}}
	portScanner, err := New(Config{
		Targets:     []string{"example.com"},
		Ports:       []int{1234},
		Workers:     1,
		DialTimeout: time.Second,
		Dialer:      dialer,
		Probes:      registry,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	var open Event
	for event := range portScanner.Scan(context.Background()) {
		if event.Kind == EventOpen {
			open = event
		}
	}
	if dialer.Calls() != 2 {
		t.Errorf("DialContext() calls = %d, want 2", dialer.Calls())
	}
	if len(open.Probes) != 2 || open.Probes[0].Protocol != "ssh" || open.Probes[0].Err != nil ||
		open.Probes[1].Protocol != "ftp" || open.Probes[1].Err != nil {
		t.Errorf("Event.Probes = %#v, want successful SSH and FTP probes", open.Probes)
	}
}

func TestScanReportsClosedPortAndAdditionalProbeDialFailure(t *testing.T) {
	t.Parallel()

	closedScanner, err := New(Config{
		Targets:     []string{"example.com"},
		Ports:       []int{443},
		Workers:     1,
		DialTimeout: time.Second,
		Dialer:      errorDialer{},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	var closed Event
	for event := range closedScanner.Scan(context.Background()) {
		if event.Kind == EventClosed {
			closed = event
		}
	}
	if closed.Err == nil || closed.Host != "example.com" || closed.Port != 443 {
		t.Errorf("closed event = %#v", closed)
	}

	registry, err := probe.NewRegistry(probe.Config{
		Timeout: time.Second,
		Definitions: []probe.Definition{
			{Name: "ssh", Ports: []int{1234}},
			{Name: "ftp", Ports: []int{1234}},
		},
	})
	if err != nil {
		t.Fatalf("probe.NewRegistry() error = %v", err)
	}
	dialer := &firstOnlyDialer{}
	probeScanner, err := New(Config{
		Targets:     []string{"example.com"},
		Ports:       []int{1234},
		Workers:     1,
		DialTimeout: time.Second,
		Dialer:      dialer,
		Probes:      registry,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	var open Event
	for event := range probeScanner.Scan(context.Background()) {
		if event.Kind == EventOpen {
			open = event
		}
	}
	if len(open.Probes) != 2 || open.Probes[0].Err != nil || open.Probes[1].Err == nil {
		t.Errorf("probe event = %#v, want first success and second dial failure", open)
	}
}

type recordingDialer struct {
	addresses chan string
}

type errorDialer struct{}

func (errorDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("connection refused")
}

type sequenceDialer struct {
	mu        sync.Mutex
	responses []string
	calls     int
}

func (d *sequenceDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.mu.Lock()
	index := d.calls
	d.calls++
	d.mu.Unlock()
	if index >= len(d.responses) {
		return nil, errors.New("no mock response")
	}
	client, server := net.Pipe()
	go func(response string) {
		defer server.Close()
		_, _ = server.Write([]byte(response))
	}(d.responses[index])
	return client, nil
}

func (d *sequenceDialer) Calls() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

type firstOnlyDialer struct {
	mu    sync.Mutex
	calls int
}

func (d *firstOnlyDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.mu.Lock()
	d.calls++
	call := d.calls
	d.mu.Unlock()
	if call > 1 {
		return nil, errors.New("proxy unavailable")
	}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		_, _ = server.Write([]byte("SSH-2.0-test\r\n"))
	}()
	return client, nil
}

func (d *recordingDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	d.addresses <- address
	client, server := net.Pipe()
	if err := server.Close(); err != nil {
		if closeErr := client.Close(); closeErr != nil {
			return nil, errors.Join(err, closeErr)
		}
		return nil, err
	}
	return client, nil
}
