package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	appconfig "github.com/hightemp/go_port_scanner/internal/config"
	"github.com/hightemp/go_port_scanner/internal/discovery"
	"github.com/hightemp/go_port_scanner/internal/probe"
	"github.com/hightemp/go_port_scanner/internal/report"
	"github.com/hightemp/go_port_scanner/internal/scanner"
)

func TestBuildReportDocument(t *testing.T) {
	t.Parallel()

	startedAt := time.Date(2026, time.August, 23, 10, 0, 0, 0, time.UTC)
	scanError := errors.New("deadline exceeded")
	document := buildReportDocument(
		startedAt,
		startedAt.Add(time.Second),
		[]string{"up", "down"},
		[]string{"up"},
		2,
		[]discovery.Result{
			{Target: "up", Alive: true, Method: discovery.StrategyTCP},
			{Target: "down", Err: errors.New("timeout")},
		},
		[]scanner.Event{{
			Kind:     scanner.EventOpen,
			Host:     "up",
			Port:     22,
			Duration: time.Millisecond,
			Probes: []probe.Result{
				{Protocol: "ssh", Duration: time.Millisecond, Detail: "OpenSSH"},
				{Protocol: "ftp", Err: errors.New("bad greeting")},
			},
		}},
		scanStats{total: 2, completed: 1, open: 1},
		scanError,
		map[string]string{"up": "up.example", "down": "down.example"},
	)

	if document.Status != "interrupted" || document.Error != scanError.Error() ||
		document.Duration != "1s" || document.PortCount != 2 || document.SchemaVersion != 2 {
		t.Errorf("document metadata = %#v", document)
	}
	if !reflect.DeepEqual(document.RequestedTargets, []string{"up", "down"}) ||
		!reflect.DeepEqual(document.ScannedTargets, []string{"up"}) {
		t.Errorf("document targets = %v / %v", document.RequestedTargets, document.ScannedTargets)
	}
	if len(document.Discovery) != 2 || !document.Discovery[0].Available ||
		document.Discovery[0].Hostname != "up.example" || document.Discovery[1].Error != "timeout" {
		t.Errorf("document discovery = %#v", document.Discovery)
	}
	if len(document.OpenPorts) != 1 || len(document.OpenPorts[0].Probes) != 2 ||
		document.OpenPorts[0].Hostname != "up.example" ||
		document.OpenPorts[0].Probes[0].Status != "ok" ||
		document.OpenPorts[0].Probes[1].Status != "failed" {
		t.Errorf("document open ports = %#v", document.OpenPorts)
	}
}

func TestBuildCompletedReportDocument(t *testing.T) {
	t.Parallel()

	startedAt := time.Now()
	document := buildReportDocument(startedAt, startedAt, nil, nil, 0, nil, nil, scanStats{}, nil, nil)
	if document.Status != "completed" || document.Error != "" {
		t.Errorf("document = %#v", document)
	}
}

func TestReportLogOutput(t *testing.T) {
	t.Parallel()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	configuration := appconfig.Default()
	if got := reportLogOutput(configuration, stdout, stderr); got != io.Writer(stdout) {
		t.Error("disabled report log output is not stdout")
	}
	configuration.Report.Enabled = true
	configuration.Report.Destination = report.DestinationStdout
	if got := reportLogOutput(configuration, stdout, stderr); got != io.Writer(stderr) {
		t.Error("stdout report log output is not stderr")
	}
}

func TestValidateReportDestination(t *testing.T) {
	t.Parallel()

	configuration := appconfig.Default()
	configuration.Report.Enabled = true
	configuration.Report.Destination = report.DestinationStdout
	if err := validateReportDestination(configuration, "config.yaml"); err != nil {
		t.Fatalf("validateReportDestination(stdout) error = %v", err)
	}

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	configuration.Report.Destination = configPath
	if err := validateReportDestination(configuration, configPath); err == nil {
		t.Fatal("validateReportDestination() error = nil, want overwrite protection")
	}
	configuration.Report.Enabled = false
	if err := validateReportDestination(configuration, configPath); err != nil {
		t.Fatalf("validateReportDestination(disabled) error = %v", err)
	}
}

func TestSameFile(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	first := filepath.Join(directory, "first")
	second := filepath.Join(directory, "second")
	if err := os.WriteFile(first, []byte("test"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	if err := os.Link(first, second); err != nil {
		t.Fatalf("os.Link() error = %v", err)
	}
	same, err := sameFile(first, second)
	if err != nil || !same {
		t.Fatalf("sameFile() = %v, %v; want true, nil", same, err)
	}
	if same, err := sameFile(first, filepath.Join(directory, "missing")); err != nil || same {
		t.Fatalf("sameFile(missing) = %v, %v; want false, nil", same, err)
	}
}

func TestWriteConfiguredReportDisabled(t *testing.T) {
	t.Parallel()

	if err := writeConfiguredReport(appconfig.Default(), report.Document{}, io.Discard, io.Discard); err != nil {
		t.Fatalf("writeConfiguredReport() error = %v", err)
	}
}

func TestWriteConfiguredReportOnlyWorking(t *testing.T) {
	t.Parallel()

	configuration := appconfig.Default()
	configuration.Report.Enabled = true
	configuration.Report.OnlyWorking = true
	configuration.Report.Destination = report.DestinationStdout
	configuration.Report.Format = appconfig.ReportFormatJSON
	document := report.Document{
		RequestedTargets: []string{"up", "down"},
		ScannedTargets:   []string{"up", "down"},
		Discovery: []report.DiscoveryResult{
			{Target: "up", Available: true},
			{Target: "down", Error: "timeout"},
		},
		OpenPorts: []report.OpenPort{{
			Target: "up",
			Port:   443,
			Probes: []report.ProbeResult{
				{Protocol: "https", Status: "ok", Detail: "HTTP 200"},
				{Protocol: "http", Status: "failed", Error: "invalid response"},
			},
		}},
		Summary: report.Summary{Total: 2, Completed: 2, Open: 1, Closed: 1, Refused: 1},
	}

	var output bytes.Buffer
	if err := writeConfiguredReport(configuration, document, &output, io.Discard); err != nil {
		t.Fatalf("writeConfiguredReport() error = %v", err)
	}
	var filtered report.Document
	if err := json.Unmarshal(output.Bytes(), &filtered); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if !reflect.DeepEqual(filtered.RequestedTargets, []string{"up"}) ||
		len(filtered.Discovery) != 1 || len(filtered.OpenPorts) != 1 ||
		len(filtered.OpenPorts[0].Probes) != 1 || filtered.OpenPorts[0].Probes[0].Protocol != "https" {
		t.Errorf("filtered report = %#v", filtered)
	}
	wantSummary := report.Summary{Total: 1, Completed: 1, Open: 1}
	if filtered.Summary != wantSummary {
		t.Errorf("filtered summary = %#v, want %#v", filtered.Summary, wantSummary)
	}
}

func TestRunWritesJSONReportToStdout(t *testing.T) {
	t.Parallel()

	listener, err := netListenLocalhost()
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer listener.Close()
	_, port, err := splitListenerAddress(listener)
	if err != nil {
		t.Fatalf("net.SplitHostPort() error = %v", err)
	}

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	yamlConfig := `
targets: [127.0.0.1]
ports: [` + port + `]
scanner:
  workers: 1
  dial_timeout: 1s
  verbosity: info
report:
  enabled: true
  destination: stdout
  format: json
`
	if err := os.WriteFile(configPath, []byte(yamlConfig), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := run(context.Background(), []string{"-config", configPath}, &stdout, &stderr); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	var document report.Document
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatalf("stdout is not a valid JSON report: %v; output=%q", err, stdout.String())
	}
	if document.Summary.Open != 1 || len(document.OpenPorts) != 1 || document.OpenPorts[0].Port == 0 {
		t.Errorf("report document = %#v", document)
	}
	for _, want := range []string{"Starting scan", "TCP: " + port, "Report written to stdout in json format"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr = %q, want it to contain %q", stderr.String(), want)
		}
	}
}

func netListenLocalhost() (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:0")
}

func splitListenerAddress(listener net.Listener) (string, string, error) {
	return net.SplitHostPort(listener.Addr().String())
}
