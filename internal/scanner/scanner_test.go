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
		Host:        "localhost",
		Workers:     1,
		StartPort:   1,
		EndPort:     1,
		DialTimeout: time.Second,
	}

	tests := []struct {
		name   string
		change func(*Config)
	}{
		{name: "empty host", change: func(config *Config) { config.Host = "" }},
		{name: "invalid start port", change: func(config *Config) { config.StartPort = 0 }},
		{name: "invalid end port", change: func(config *Config) { config.EndPort = maxPort + 1 }},
		{name: "reversed range", change: func(config *Config) { config.StartPort, config.EndPort = 2, 1 }},
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

	scanner, err := New(Config{
		Host:        "localhost",
		Workers:     100,
		StartPort:   80,
		EndPort:     81,
		DialTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got, want := scanner.Workers(), 2; got != want {
		t.Errorf("Workers() = %d, want %d", got, want)
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
		Host:        "127.0.0.1",
		Workers:     1,
		StartPort:   port,
		EndPort:     port,
		DialTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	var kinds []EventKind
	for event := range portScanner.Scan(context.Background()) {
		kinds = append(kinds, event.Kind)
	}

	if len(kinds) != 2 || kinds[0] != EventChecking || kinds[1] != EventOpen {
		t.Fatalf("Scan() event kinds = %v, want [%v %v]", kinds, EventChecking, EventOpen)
	}
}
