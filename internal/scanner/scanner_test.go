package scanner

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
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
