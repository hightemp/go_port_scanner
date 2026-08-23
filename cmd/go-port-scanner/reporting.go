package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	appconfig "github.com/hightemp/go_port_scanner/internal/config"
	"github.com/hightemp/go_port_scanner/internal/discovery"
	"github.com/hightemp/go_port_scanner/internal/report"
	"github.com/hightemp/go_port_scanner/internal/scanner"
)

func reportLogOutput(configuration appconfig.Config, stdout, stderr io.Writer) io.Writer {
	if configuration.Report.Enabled &&
		strings.TrimSpace(configuration.Report.Destination) == report.DestinationStdout {
		return stderr
	}
	return stdout
}

func validateReportDestination(configuration appconfig.Config, configPath string) error {
	if !configuration.Report.Enabled {
		return nil
	}
	destination := strings.TrimSpace(configuration.Report.Destination)
	if destination == report.DestinationStdout || destination == report.DestinationStderr || configPath == "" {
		return nil
	}

	same, err := sameFile(destination, configPath)
	if err != nil {
		return fmt.Errorf("compare report destination with config path: %w", err)
	}
	if same {
		return errors.New("report.destination must not overwrite the active configuration file")
	}
	return nil
}

func sameFile(left, right string) (bool, error) {
	leftAbsolute, err := filepath.Abs(left)
	if err != nil {
		return false, fmt.Errorf("resolve %q: %w", left, err)
	}
	rightAbsolute, err := filepath.Abs(right)
	if err != nil {
		return false, fmt.Errorf("resolve %q: %w", right, err)
	}
	if filepath.Clean(leftAbsolute) == filepath.Clean(rightAbsolute) {
		return true, nil
	}

	leftInfo, leftErr := os.Stat(leftAbsolute)
	rightInfo, rightErr := os.Stat(rightAbsolute)
	if leftErr == nil && rightErr == nil {
		return os.SameFile(leftInfo, rightInfo), nil
	}
	if leftErr != nil && !errors.Is(leftErr, os.ErrNotExist) {
		return false, fmt.Errorf("stat %q: %w", leftAbsolute, leftErr)
	}
	if rightErr != nil && !errors.Is(rightErr, os.ErrNotExist) {
		return false, fmt.Errorf("stat %q: %w", rightAbsolute, rightErr)
	}
	return false, nil
}

func buildReportDocument(
	startedAt time.Time,
	finishedAt time.Time,
	requestedTargets []string,
	scannedTargets []string,
	portCount int,
	discoveryResults []discovery.Result,
	openEvents []scanner.Event,
	statistics scanStats,
	scanError error,
) report.Document {
	status := "completed"
	errorMessage := ""
	if scanError != nil {
		status = "interrupted"
		errorMessage = scanError.Error()
	}

	document := report.Document{
		SchemaVersion:    1,
		Status:           status,
		StartedAt:        startedAt,
		FinishedAt:       finishedAt,
		Duration:         finishedAt.Sub(startedAt).String(),
		RequestedTargets: append([]string(nil), requestedTargets...),
		ScannedTargets:   append([]string(nil), scannedTargets...),
		PortCount:        portCount,
		Discovery:        make([]report.DiscoveryResult, 0, len(discoveryResults)),
		OpenPorts:        make([]report.OpenPort, 0, len(openEvents)),
		Summary: report.Summary{
			Total:       statistics.total,
			Completed:   statistics.completed,
			Open:        statistics.open,
			Closed:      statistics.closed,
			Timeouts:    statistics.timeouts,
			Refused:     statistics.refused,
			Unreachable: statistics.unreachable,
			OtherErrors: statistics.otherErrors,
		},
		Error: errorMessage,
	}

	for _, result := range discoveryResults {
		discoveryResult := report.DiscoveryResult{
			Target:    result.Target,
			Available: result.Alive,
			Method:    string(result.Method),
		}
		if result.Err != nil {
			discoveryResult.Error = result.Err.Error()
		}
		document.Discovery = append(document.Discovery, discoveryResult)
	}
	for _, event := range openEvents {
		openPort := report.OpenPort{
			Target:   event.Host,
			Port:     event.Port,
			Duration: event.Duration.String(),
			Probes:   make([]report.ProbeResult, 0, len(event.Probes)),
		}
		for _, result := range event.Probes {
			probeResult := report.ProbeResult{
				Protocol: result.Protocol,
				Status:   "ok",
				Duration: result.Duration.String(),
				Detail:   result.Detail,
			}
			if result.Err != nil {
				probeResult.Status = "failed"
				probeResult.Error = result.Err.Error()
			}
			openPort.Probes = append(openPort.Probes, probeResult)
		}
		document.OpenPorts = append(document.OpenPorts, openPort)
	}
	return document
}

func writeConfiguredReport(
	configuration appconfig.Config,
	document report.Document,
	stdout io.Writer,
	stderr io.Writer,
) error {
	if !configuration.Report.Enabled {
		return nil
	}
	if err := report.WriteDestination(
		configuration.Report.Destination,
		report.Format(configuration.Report.Format),
		document,
		stdout,
		stderr,
	); err != nil {
		return fmt.Errorf("write configured report: %w", err)
	}
	return nil
}
