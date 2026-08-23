package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	appconfig "github.com/hightemp/go_port_scanner/internal/config"
	"github.com/hightemp/go_port_scanner/internal/report"
)

func TestOpenLogOutput(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "nested", "scanner.log")
	var terminal bytes.Buffer
	write := func(message string) {
		t.Helper()
		output, file, err := openLogOutput(path, &terminal)
		if err != nil {
			t.Fatalf("openLogOutput() error = %v", err)
		}
		if _, err := io.WriteString(output, message); err != nil {
			t.Errorf("WriteString() error = %v", err)
		}
		if err := file.Close(); err != nil {
			t.Errorf("log file Close() error = %v", err)
		}
	}

	write("first\n")
	write("second\n")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	const want = "first\nsecond\n"
	if got := string(contents); got != want {
		t.Errorf("log file = %q, want %q", got, want)
	}
	if got := terminal.String(); got != want {
		t.Errorf("terminal output = %q, want %q", got, want)
	}
}

func TestOpenLogOutputDisabled(t *testing.T) {
	t.Parallel()

	terminal := &bytes.Buffer{}
	output, file, err := openLogOutput("", terminal)
	if err != nil || output != io.Writer(terminal) || file != nil {
		t.Fatalf("openLogOutput(disabled) = %T, %v, %v", output, file, err)
	}
}

func TestValidateLogFileDestination(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.yaml")
	logPath := filepath.Join(directory, "scanner.log")
	reportPath := filepath.Join(directory, "report.json")
	configuration := appconfig.Default()

	tests := []struct {
		name       string
		logPath    string
		configPath string
		report     string
		wantError  bool
	}{
		{name: "disabled"},
		{name: "separate file", logPath: logPath, configPath: configPath},
		{name: "configuration collision", logPath: configPath, configPath: configPath, wantError: true},
		{name: "report collision", logPath: reportPath, configPath: configPath, report: reportPath, wantError: true},
		{name: "stdout report", logPath: logPath, configPath: configPath, report: report.DestinationStdout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := configuration
			candidate.Scanner.LogFile = tt.logPath
			if tt.report != "" {
				candidate.Report.Enabled = true
				candidate.Report.Destination = tt.report
			}
			err := validateLogFileDestination(candidate, tt.configPath)
			if (err != nil) != tt.wantError {
				t.Fatalf("validateLogFileDestination() error = %v, wantError = %v", err, tt.wantError)
			}
		})
	}
}

func TestRunWritesLogFile(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.yaml")
	logPath := filepath.Join(directory, "logs", "scanner.log")
	configuration := fmt.Sprintf(`
targets: [127.0.0.1]
ports: [1]
scanner:
  workers: 1
  progress_interval: 0s
  verbosity: info
  log_file: %q
`, logPath)
	if err := os.WriteFile(configPath, []byte(configuration), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	var stdout bytes.Buffer
	if err := run(context.Background(), []string{"-config", configPath}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	contents, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	for _, output := range []string{stdout.String(), string(contents)} {
		if !strings.Contains(output, "Starting scan") || !strings.Contains(output, "Scan completed") {
			t.Errorf("log output = %q, want scan lifecycle messages", output)
		}
	}
}
