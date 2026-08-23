package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	appconfig "github.com/hightemp/go_port_scanner/internal/config"
	"github.com/hightemp/go_port_scanner/internal/logging"
)

func TestResolveHostnames(t *testing.T) {
	t.Parallel()

	resolver := mainReverseDNSResolver{responses: map[string]mainReverseDNSResponse{
		"192.0.2.1": {names: []string{"router.example."}},
		"192.0.2.2": {err: errors.New("no such host")},
	}}
	settings := appconfig.ReverseDNS{
		Enabled: true,
		Workers: 2,
		Timeout: appconfig.Duration{Duration: time.Second},
	}
	var output bytes.Buffer
	hostnames, err := resolveHostnames(
		context.Background(),
		logging.New(&output, logging.DebugLevel),
		[]string{"192.0.2.1", "example.com", "192.0.2.2"},
		settings,
		resolver,
	)
	if err != nil {
		t.Fatalf("resolveHostnames() error = %v", err)
	}
	if len(hostnames) != 1 || hostnames["192.0.2.1"] != "router.example" {
		t.Errorf("resolveHostnames() = %#v", hostnames)
	}
	for _, want := range []string{
		"Resolving reverse DNS names with 2 workers",
		"Reverse DNS resolved 192.0.2.1 to router.example",
		"Reverse DNS lookup for 192.0.2.2 failed",
		"1/2 IP target(s) resolved",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("log output = %q, want %q", output.String(), want)
		}
	}
}

type mainReverseDNSResponse struct {
	names []string
	err   error
}

type mainReverseDNSResolver struct {
	responses map[string]mainReverseDNSResponse
}

func (resolver mainReverseDNSResolver) LookupAddr(_ context.Context, address string) ([]string, error) {
	response := resolver.responses[address]
	return response.names, response.err
}
