package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestWriteFormats(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		format Format
		check  func(*testing.T, string)
	}{
		{
			name:   "text",
			format: FormatText,
			check: func(t *testing.T, output string) {
				t.Helper()
				for _, want := range []string{
					"Go Port Scanner report",
					"DISCOVERY host-a (alpha.example): available via tcp",
					"REQUESTED host-a",
					"SCANNED host-b",
					"OPEN host-a:80 (alpha.example)",
					"OPEN host-b:443",
					`danger\nline`,
					"SUMMARY completed=4/4 open=2 closed=2",
				} {
					if !strings.Contains(output, want) {
						t.Errorf("text report = %q, want it to contain %q", output, want)
					}
				}
			},
		},
		{
			name:   "JSON",
			format: FormatJSON,
			check: func(t *testing.T, output string) {
				t.Helper()
				var document Document
				if err := json.Unmarshal([]byte(output), &document); err != nil {
					t.Fatalf("json.Unmarshal() error = %v", err)
				}
				if document.SchemaVersion != 2 || len(document.OpenPorts) != 2 ||
					document.OpenPorts[0].Target != "host-a" || document.OpenPorts[0].Hostname != "alpha.example" ||
					document.OpenPorts[1].Target != "host-b" {
					t.Errorf("JSON document = %#v", document)
				}
			},
		},
		{
			name:   "JSONL",
			format: FormatJSONL,
			check: func(t *testing.T, output string) {
				t.Helper()
				lines := strings.Split(strings.TrimSpace(output), "\n")
				if len(lines) != 6 {
					t.Fatalf("JSONL line count = %d, want 6", len(lines))
				}
				var first jsonLine
				if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
					t.Fatalf("json.Unmarshal() error = %v", err)
				}
				if first.Type != "metadata" || first.Metadata == nil || first.Metadata.Status != "completed" {
					t.Errorf("first JSONL record = %#v", first)
				}
				var last jsonLine
				if err := json.Unmarshal([]byte(lines[len(lines)-1]), &last); err != nil {
					t.Fatalf("json.Unmarshal() error = %v", err)
				}
				if last.Type != "summary" || last.Summary == nil || last.Summary.Open != 2 {
					t.Errorf("last JSONL record = %#v", last)
				}
			},
		},
		{
			name:   "CSV",
			format: FormatCSV,
			check: func(t *testing.T, output string) {
				t.Helper()
				rows, err := csv.NewReader(strings.NewReader(output)).ReadAll()
				if err != nil {
					t.Fatalf("csv.ReadAll() error = %v", err)
				}
				if len(rows) < 10 || !reflect.DeepEqual(rows[0], []string{
					"record_type", "target", "hostname", "port", "duration", "protocol", "status", "detail", "error", "metric", "value",
				}) {
					t.Fatalf("CSV rows = %#v", rows)
				}
				foundSafeDetail := false
				for _, row := range rows {
					if row[0] == "probe" && row[2] == "alpha.example" && row[7] == "'=danger\nline" {
						foundSafeDetail = true
					}
				}
				if !foundSafeDetail {
					t.Errorf("CSV report does not contain protected formula field: %#v", rows)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var output bytes.Buffer
			if err := Write(&output, tt.format, testDocument()); err != nil {
				t.Fatalf("Write() error = %v", err)
			}
			tt.check(t, output.String())
		})
	}
}

func TestWriteErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		format Format
		writer io.Writer
	}{
		{name: "unknown format", format: "xml", writer: &bytes.Buffer{}},
		{name: "writer error", format: FormatJSON, writer: reportErrorWriter{}},
		{name: "short write", format: FormatJSON, writer: reportShortWriter{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := Write(tt.writer, tt.format, testDocument()); err == nil {
				t.Fatal("Write() error = nil, want error")
			}
		})
	}
}

func TestWriteDestination(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		destination string
		wantStdout  bool
		wantStderr  bool
		wantFile    bool
	}{
		{name: "stdout", destination: DestinationStdout, wantStdout: true},
		{name: "stderr", destination: DestinationStderr, wantStderr: true},
		{name: "file", destination: "nested/report.json", wantFile: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout bytes.Buffer
			var stderr bytes.Buffer
			destination := tt.destination
			if tt.wantFile {
				destination = filepath.Join(t.TempDir(), destination)
			}
			if err := WriteDestination(destination, FormatJSON, testDocument(), &stdout, &stderr); err != nil {
				t.Fatalf("WriteDestination() error = %v", err)
			}
			if tt.wantStdout != (stdout.Len() > 0) || tt.wantStderr != (stderr.Len() > 0) {
				t.Errorf("stdout=%d stderr=%d", stdout.Len(), stderr.Len())
			}
			if tt.wantFile {
				data, err := os.ReadFile(destination)
				if err != nil {
					t.Fatalf("os.ReadFile() error = %v", err)
				}
				if !json.Valid(data) {
					t.Errorf("file report is not valid JSON: %q", data)
				}
				info, err := os.Stat(destination)
				if err != nil {
					t.Fatalf("os.Stat() error = %v", err)
				}
				if permissions := info.Mode().Perm(); permissions != 0o600 {
					t.Errorf("report permissions = %#o, want 0600", permissions)
				}
			}
		})
	}
}

func TestWriteDestinationRejectsEmpty(t *testing.T) {
	t.Parallel()
	if err := WriteDestination(" ", FormatJSON, testDocument(), io.Discard, io.Discard); err == nil {
		t.Fatal("WriteDestination() error = nil, want empty destination error")
	}
}

func testDocument() Document {
	startedAt := time.Date(2026, time.August, 23, 10, 0, 0, 0, time.UTC)
	return Document{
		SchemaVersion:    2,
		Status:           "completed",
		StartedAt:        startedAt,
		FinishedAt:       startedAt.Add(2 * time.Second),
		Duration:         "2s",
		RequestedTargets: []string{"host-a", "host-b"},
		ScannedTargets:   []string{"host-a", "host-b"},
		PortCount:        2,
		Discovery: []DiscoveryResult{
			{Target: "host-a", Hostname: "alpha.example", Available: true, Method: "tcp"},
			{Target: "host-b", Available: false, Error: "timeout"},
		},
		OpenPorts: []OpenPort{
			{Target: "host-b", Port: 443, Duration: "2ms"},
			{
				Target:   "host-a",
				Hostname: "alpha.example",
				Port:     80,
				Duration: "1ms",
				Probes: []ProbeResult{
					{Protocol: "http", Status: "ok", Duration: "500µs", Detail: "=danger\nline"},
					{Protocol: "https", Status: "failed", Error: "TLS handshake failed"},
				},
			},
		},
		Summary: Summary{Total: 4, Completed: 4, Open: 2, Closed: 2, Refused: 2},
	}
}

type reportErrorWriter struct{}

func (reportErrorWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

type reportShortWriter struct{}

func (reportShortWriter) Write(buffer []byte) (int, error) {
	return len(buffer) - 1, nil
}
