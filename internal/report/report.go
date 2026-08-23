// Package report serializes completed and interrupted port scan reports.
package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Format controls report serialization.
type Format string

const (
	// FormatText writes a human-readable report.
	FormatText Format = "text"
	// FormatJSON writes one structured JSON document.
	FormatJSON Format = "json"
	// FormatJSONL writes one JSON record per line.
	FormatJSONL Format = "jsonl"
	// FormatCSV writes normalized comma-separated records.
	FormatCSV Format = "csv"

	// DestinationStdout writes a report to standard output.
	DestinationStdout = "stdout"
	// DestinationStderr writes a report to standard error.
	DestinationStderr = "stderr"
)

// Document is the complete serializable result of one scan.
type Document struct {
	SchemaVersion    int               `json:"schema_version"`
	Status           string            `json:"status"`
	StartedAt        time.Time         `json:"started_at"`
	FinishedAt       time.Time         `json:"finished_at"`
	Duration         string            `json:"duration"`
	RequestedTargets []string          `json:"requested_targets"`
	ScannedTargets   []string          `json:"scanned_targets"`
	PortCount        int               `json:"port_count"`
	Discovery        []DiscoveryResult `json:"discovery,omitempty"`
	OpenPorts        []OpenPort        `json:"open_ports"`
	Summary          Summary           `json:"summary"`
	Error            string            `json:"error,omitempty"`
}

// DiscoveryResult describes whether one requested host passed discovery.
type DiscoveryResult struct {
	Target    string `json:"target"`
	Hostname  string `json:"hostname,omitempty"`
	Available bool   `json:"available"`
	Method    string `json:"method,omitempty"`
	Error     string `json:"error,omitempty"`
}

// OpenPort describes one successful TCP connection and optional probes.
type OpenPort struct {
	Target   string        `json:"target"`
	Hostname string        `json:"hostname,omitempty"`
	Port     int           `json:"port"`
	Duration string        `json:"duration"`
	Probes   []ProbeResult `json:"probes,omitempty"`
}

// ProbeResult describes one application protocol handshake.
type ProbeResult struct {
	Protocol string `json:"protocol"`
	Status   string `json:"status"`
	Duration string `json:"duration"`
	Detail   string `json:"detail,omitempty"`
	Error    string `json:"error,omitempty"`
}

// Summary contains aggregate TCP result counters.
type Summary struct {
	Total       int `json:"total"`
	Completed   int `json:"completed"`
	Open        int `json:"open"`
	Closed      int `json:"closed"`
	Timeouts    int `json:"timeouts"`
	Refused     int `json:"refused"`
	Unreachable int `json:"unreachable"`
	OtherErrors int `json:"other_errors"`
}

// Write serializes document to writer using format.
func Write(writer io.Writer, format Format, document Document) error {
	document = normalize(document)
	var buffer bytes.Buffer
	var err error
	switch format {
	case FormatText:
		err = writeText(&buffer, document)
	case FormatJSON:
		err = writeJSON(&buffer, document)
	case FormatJSONL:
		err = writeJSONL(&buffer, document)
	case FormatCSV:
		err = writeCSV(&buffer, document)
	default:
		return fmt.Errorf("unsupported report format %q", format)
	}
	if err != nil {
		return err
	}

	written, err := writer.Write(buffer.Bytes())
	if err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	if written != buffer.Len() {
		return fmt.Errorf("write report: %w", io.ErrShortWrite)
	}
	return nil
}

// WriteDestination writes a report to stdout, stderr, or a file path. Missing
// parent directories for file destinations are created automatically.
func WriteDestination(
	destination string,
	format Format,
	document Document,
	stdout io.Writer,
	stderr io.Writer,
) (resultErr error) {
	destination = strings.TrimSpace(destination)
	switch destination {
	case DestinationStdout:
		return Write(stdout, format, document)
	case DestinationStderr:
		return Write(stderr, format, document)
	case "":
		return errors.New("report destination must not be empty")
	}

	directory := filepath.Dir(destination)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return fmt.Errorf("create report directory %q: %w", directory, err)
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open report %q: %w", destination, err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close report %q: %w", destination, closeErr))
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("set report permissions %q: %w", destination, err)
	}

	if err := Write(file, format, document); err != nil {
		return fmt.Errorf("write report %q: %w", destination, err)
	}
	return nil
}

func normalize(document Document) Document {
	document.RequestedTargets = append([]string(nil), document.RequestedTargets...)
	document.ScannedTargets = append([]string(nil), document.ScannedTargets...)
	document.Discovery = append([]DiscoveryResult(nil), document.Discovery...)
	document.OpenPorts = append([]OpenPort(nil), document.OpenPorts...)
	targetOrder := make(map[string]int, len(document.ScannedTargets))
	for index, target := range document.ScannedTargets {
		targetOrder[target] = index
	}
	sort.SliceStable(document.OpenPorts, func(left, right int) bool {
		leftOrder, leftExists := targetOrder[document.OpenPorts[left].Target]
		rightOrder, rightExists := targetOrder[document.OpenPorts[right].Target]
		if leftExists && rightExists && leftOrder != rightOrder {
			return leftOrder < rightOrder
		}
		if leftExists != rightExists {
			return leftExists
		}
		if document.OpenPorts[left].Target != document.OpenPorts[right].Target {
			return document.OpenPorts[left].Target < document.OpenPorts[right].Target
		}
		return document.OpenPorts[left].Port < document.OpenPorts[right].Port
	})
	return document
}

func writeJSON(writer io.Writer, document Document) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(document); err != nil {
		return fmt.Errorf("encode JSON report: %w", err)
	}
	return nil
}

type jsonLine struct {
	Type      string           `json:"type"`
	Metadata  *reportMetadata  `json:"metadata,omitempty"`
	Discovery *DiscoveryResult `json:"discovery,omitempty"`
	OpenPort  *OpenPort        `json:"open_port,omitempty"`
	Summary   *Summary         `json:"summary,omitempty"`
}

type reportMetadata struct {
	SchemaVersion    int       `json:"schema_version"`
	Status           string    `json:"status"`
	StartedAt        time.Time `json:"started_at"`
	FinishedAt       time.Time `json:"finished_at"`
	Duration         string    `json:"duration"`
	RequestedTargets []string  `json:"requested_targets"`
	ScannedTargets   []string  `json:"scanned_targets"`
	PortCount        int       `json:"port_count"`
	Error            string    `json:"error,omitempty"`
}

func writeJSONL(writer io.Writer, document Document) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	metadata := reportMetadata{
		SchemaVersion:    document.SchemaVersion,
		Status:           document.Status,
		StartedAt:        document.StartedAt,
		FinishedAt:       document.FinishedAt,
		Duration:         document.Duration,
		RequestedTargets: document.RequestedTargets,
		ScannedTargets:   document.ScannedTargets,
		PortCount:        document.PortCount,
		Error:            document.Error,
	}
	if err := encoder.Encode(jsonLine{Type: "metadata", Metadata: &metadata}); err != nil {
		return fmt.Errorf("encode JSONL metadata: %w", err)
	}
	for index := range document.Discovery {
		if err := encoder.Encode(jsonLine{Type: "discovery", Discovery: &document.Discovery[index]}); err != nil {
			return fmt.Errorf("encode JSONL discovery result: %w", err)
		}
	}
	for index := range document.OpenPorts {
		if err := encoder.Encode(jsonLine{Type: "open_port", OpenPort: &document.OpenPorts[index]}); err != nil {
			return fmt.Errorf("encode JSONL open port: %w", err)
		}
	}
	if err := encoder.Encode(jsonLine{Type: "summary", Summary: &document.Summary}); err != nil {
		return fmt.Errorf("encode JSONL summary: %w", err)
	}
	return nil
}

func writeText(writer io.Writer, document Document) error {
	lines := []string{
		"Go Port Scanner report",
		"status: " + document.Status,
		"started_at: " + document.StartedAt.Format(time.RFC3339Nano),
		"finished_at: " + document.FinishedAt.Format(time.RFC3339Nano),
		"duration: " + document.Duration,
		fmt.Sprintf("targets: %d requested, %d scanned", len(document.RequestedTargets), len(document.ScannedTargets)),
		fmt.Sprintf("ports_per_target: %d", document.PortCount),
	}
	if document.Error != "" {
		lines = append(lines, "error: "+textSafe(document.Error))
	}
	for _, target := range document.RequestedTargets {
		lines = append(lines, "REQUESTED "+textSafe(target))
	}
	for _, target := range document.ScannedTargets {
		lines = append(lines, "SCANNED "+textSafe(target))
	}
	for _, result := range document.Discovery {
		status := "unavailable"
		if result.Available {
			status = "available"
		}
		line := fmt.Sprintf("DISCOVERY %s: %s", targetWithHostname(result.Target, result.Hostname), status)
		if result.Method != "" {
			line += " via " + result.Method
		}
		if result.Error != "" {
			line += " (" + textSafe(result.Error) + ")"
		}
		lines = append(lines, line)
	}
	for _, openPort := range document.OpenPorts {
		lines = append(lines, fmt.Sprintf(
			"OPEN %s in %s",
			targetWithHostname(net.JoinHostPort(openPort.Target, strconv.Itoa(openPort.Port)), openPort.Hostname),
			openPort.Duration,
		))
		for _, probe := range openPort.Probes {
			line := fmt.Sprintf("  PROBE %s: %s in %s", probe.Protocol, probe.Status, probe.Duration)
			if probe.Detail != "" {
				line += " (" + textSafe(probe.Detail) + ")"
			}
			if probe.Error != "" {
				line += " (" + textSafe(probe.Error) + ")"
			}
			lines = append(lines, line)
		}
	}
	lines = append(lines, fmt.Sprintf(
		"SUMMARY completed=%d/%d open=%d closed=%d timeouts=%d refused=%d unreachable=%d other_errors=%d",
		document.Summary.Completed,
		document.Summary.Total,
		document.Summary.Open,
		document.Summary.Closed,
		document.Summary.Timeouts,
		document.Summary.Refused,
		document.Summary.Unreachable,
		document.Summary.OtherErrors,
	))
	if _, err := io.WriteString(writer, strings.Join(lines, "\n")+"\n"); err != nil {
		return fmt.Errorf("encode text report: %w", err)
	}
	return nil
}

func writeCSV(writer io.Writer, document Document) error {
	csvWriter := csv.NewWriter(writer)
	rows := [][]string{{"record_type", "target", "hostname", "port", "duration", "protocol", "status", "detail", "error", "metric", "value"}}
	metadata := [][2]string{
		{"schema_version", strconv.Itoa(document.SchemaVersion)},
		{"status", document.Status},
		{"started_at", document.StartedAt.Format(time.RFC3339Nano)},
		{"finished_at", document.FinishedAt.Format(time.RFC3339Nano)},
		{"duration", document.Duration},
		{"port_count", strconv.Itoa(document.PortCount)},
	}
	if document.Error != "" {
		metadata = append(metadata, [2]string{"error", document.Error})
	}
	for _, item := range metadata {
		rows = append(rows, csvRow("metadata", "", "", "", "", "", "", "", "", item[0], item[1]))
	}
	for _, target := range document.RequestedTargets {
		rows = append(rows, csvRow("requested_target", target, "", "", "", "", "requested", "", "", "", ""))
	}
	for _, target := range document.ScannedTargets {
		rows = append(rows, csvRow("scanned_target", target, "", "", "", "", "scanned", "", "", "", ""))
	}
	for _, result := range document.Discovery {
		status := "unavailable"
		if result.Available {
			status = "available"
		}
		rows = append(rows, csvRow("discovery", result.Target, result.Hostname, "", "", result.Method, status, "", result.Error, "", ""))
	}
	for _, openPort := range document.OpenPorts {
		rows = append(rows, csvRow(
			"open_port",
			openPort.Target,
			openPort.Hostname,
			strconv.Itoa(openPort.Port),
			openPort.Duration,
			"tcp",
			"open",
			"",
			"",
			"",
			"",
		))
		for _, probe := range openPort.Probes {
			rows = append(rows, csvRow(
				"probe",
				openPort.Target,
				openPort.Hostname,
				strconv.Itoa(openPort.Port),
				probe.Duration,
				probe.Protocol,
				probe.Status,
				probe.Detail,
				probe.Error,
				"",
				"",
			))
		}
	}
	summary := [][2]string{
		{"total", strconv.Itoa(document.Summary.Total)},
		{"completed", strconv.Itoa(document.Summary.Completed)},
		{"open", strconv.Itoa(document.Summary.Open)},
		{"closed", strconv.Itoa(document.Summary.Closed)},
		{"timeouts", strconv.Itoa(document.Summary.Timeouts)},
		{"refused", strconv.Itoa(document.Summary.Refused)},
		{"unreachable", strconv.Itoa(document.Summary.Unreachable)},
		{"other_errors", strconv.Itoa(document.Summary.OtherErrors)},
	}
	for _, item := range summary {
		rows = append(rows, csvRow("summary", "", "", "", "", "", "", "", "", item[0], item[1]))
	}
	if err := csvWriter.WriteAll(rows); err != nil {
		return fmt.Errorf("encode CSV report: %w", err)
	}
	return nil
}

func csvRow(values ...string) []string {
	row := make([]string, len(values))
	for index, value := range values {
		row[index] = csvSafe(value)
	}
	return row
}

func csvSafe(value string) string {
	if value == "" {
		return value
	}
	switch value[0] {
	case '=', '+', '-', '@':
		return "'" + value
	default:
		return value
	}
}

func textSafe(value string) string {
	value = strings.ReplaceAll(value, "\r", "\\r")
	return strings.ReplaceAll(value, "\n", "\\n")
}

func targetWithHostname(target, hostname string) string {
	target = textSafe(target)
	if hostname == "" {
		return target
	}
	return target + " (" + textSafe(hostname) + ")"
}
