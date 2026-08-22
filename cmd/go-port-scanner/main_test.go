package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
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
			args:   []string{"-workers", "0"},
			stdout: &bytes.Buffer{},
			want:   "workers must be greater than zero",
		},
		{
			name:   "cancelled context",
			ctx:    cancelledContext,
			args:   []string{"-workers", "1", "-start", "1", "-end", "1"},
			stdout: &bytes.Buffer{},
			want:   "scan interrupted",
		},
		{
			name:   "output failure",
			ctx:    context.Background(),
			args:   []string{"-host", "127.0.0.1", "-workers", "1", "-start", "1", "-end", "1", "-v"},
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

type mainFailingWriter struct{}

func (mainFailingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}
