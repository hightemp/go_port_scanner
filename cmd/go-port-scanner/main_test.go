package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hightemp/go_port_scanner/internal/cli"
	appconfig "github.com/hightemp/go_port_scanner/internal/config"
)

func TestRunFindsOpenPort(t *testing.T) {
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

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("net.SplitHostPort() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	args := []string{
		"-config", "",
		"-host", "127.0.0.1",
		"-workers", "2",
		"-start", port,
		"-end", port,
		"-vv",
	}

	if err := run(context.Background(), args, &stdout, &stderr); err != nil {
		t.Fatalf("run() error = %v, stderr = %q", err, stderr.String())
	}

	portNumber, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("strconv.Atoi() error = %v", err)
	}
	if want := "TCP: " + strconv.Itoa(portNumber); !strings.Contains(stdout.String(), want) {
		t.Errorf("run() output = %q, want it to contain %q", stdout.String(), want)
	}
}

func TestRunUsesProxyPool(t *testing.T) {
	t.Parallel()

	proxyServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodConnect {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer proxyServer.Close()

	configPath := t.TempDir() + "/config.yaml"
	yamlConfig := fmt.Sprintf(`
targets: [example.com]
ports: [443]
scanner:
  workers: 1
  dial_timeout: 1s
  scan_timeout: 0s
  verbosity: info
proxy:
  enabled: true
  strategy: round_robin
  urls: [%q]
`, proxyServer.URL)
	if err := os.WriteFile(configPath, []byte(yamlConfig), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	var stdout bytes.Buffer
	if err := run(context.Background(), []string{"-config", configPath}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if !strings.Contains(stdout.String(), "Proxy pool enabled with 1 proxies (round_robin)") ||
		!strings.Contains(stdout.String(), "TCP: 443") {
		t.Errorf("run() output = %q, want proxy pool and open port messages", stdout.String())
	}
}

func TestRunErrors(t *testing.T) {
	t.Parallel()

	cancelledContext, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name   string
		ctx    context.Context
		args   []string
		stdout io.Writer
		want   string
	}{
		{
			name:   "invalid flag",
			ctx:    context.Background(),
			args:   []string{"-workers", "invalid"},
			stdout: &bytes.Buffer{},
			want:   "parse arguments",
		},
		{
			name:   "invalid configuration",
			ctx:    context.Background(),
			args:   []string{"-config", "", "-workers", "0"},
			stdout: &bytes.Buffer{},
			want:   "workers must be greater than zero",
		},
		{
			name:   "cancelled context",
			ctx:    cancelledContext,
			args:   []string{"-config", "", "-workers", "1", "-start", "1", "-end", "1"},
			stdout: &bytes.Buffer{},
			want:   "scan interrupted",
		},
		{
			name:   "output failure",
			ctx:    context.Background(),
			args:   []string{"-config", "", "-host", "127.0.0.1", "-workers", "1", "-start", "1", "-end", "1", "-v"},
			stdout: mainFailingWriter{},
			want:   "write log output",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := run(tt.ctx, tt.args, tt.stdout, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("run() error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestRunHelp(t *testing.T) {
	t.Parallel()

	var stderr bytes.Buffer
	if err := run(context.Background(), []string{"-h"}, &bytes.Buffer{}, &stderr); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if !strings.Contains(stderr.String(), "Usage of go_port_scanner") {
		t.Errorf("run() help = %q, want usage", stderr.String())
	}
}

func TestLoadConfigAppliesOverrides(t *testing.T) {
	t.Parallel()

	host := "127.0.0.1"
	workers := 4
	startPort := 80
	endPort := 82
	dialTimeout := 250 * time.Millisecond
	scanTimeout := time.Minute
	verbosityLevel := 3

	got, err := loadConfig(cli.Options{
		ConfigPath:  "",
		Host:        &host,
		Workers:     &workers,
		StartPort:   &startPort,
		EndPort:     &endPort,
		DialTimeout: &dialTimeout,
		ScanTimeout: &scanTimeout,
		Verbosity:   &verbosityLevel,
	})
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}

	if !slices.Equal(got.Targets, []string{host}) {
		t.Errorf("Targets = %v, want [%s]", got.Targets, host)
	}
	if !slices.Equal(got.ExpandedPorts(), []int{80, 81, 82}) {
		t.Errorf("ExpandedPorts() = %v, want [80 81 82]", got.ExpandedPorts())
	}
	if got.Scanner.Workers != workers ||
		got.Scanner.DialTimeout.Duration != dialTimeout ||
		got.Scanner.ScanTimeout.Duration != scanTimeout ||
		got.Scanner.Verbosity != appconfig.VerbosityTrace {
		t.Errorf("Scanner overrides were not applied: %#v", got.Scanner)
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	t.Parallel()

	_, err := loadConfig(cli.Options{ConfigPath: t.TempDir() + "/missing.yaml"})
	if err == nil || !strings.Contains(err.Error(), "open config") {
		t.Fatalf("loadConfig() error = %v, want open config error", err)
	}
}

func TestVerbosity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		level int
		want  appconfig.Verbosity
	}{
		{level: 0, want: appconfig.VerbosityQuiet},
		{level: 1, want: appconfig.VerbosityInfo},
		{level: 2, want: appconfig.VerbosityDebug},
		{level: 3, want: appconfig.VerbosityTrace},
	}

	for _, tt := range tests {
		t.Run(strconv.Itoa(tt.level), func(t *testing.T) {
			t.Parallel()

			if got := verbosity(tt.level); got != tt.want {
				t.Errorf("verbosity(%d) = %q, want %q", tt.level, got, tt.want)
			}
		})
	}
}

type mainFailingWriter struct{}

func (mainFailingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}
