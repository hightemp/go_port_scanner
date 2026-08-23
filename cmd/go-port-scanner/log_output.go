package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	appconfig "github.com/hightemp/go_port_scanner/internal/config"
	"github.com/hightemp/go_port_scanner/internal/report"
)

func openLogOutput(path string, terminal io.Writer) (io.Writer, *os.File, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return terminal, nil, nil
	}

	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return nil, nil, fmt.Errorf("create log directory %q: %w", directory, err)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open log file %q: %w", path, err)
	}
	if err := file.Chmod(0o600); err != nil {
		closeErr := file.Close()
		return nil, nil, errors.Join(
			fmt.Errorf("set log file permissions %q: %w", path, err),
			wrapLogCloseError(path, closeErr),
		)
	}
	return io.MultiWriter(terminal, file), file, nil
}

func validateLogFileDestination(configuration appconfig.Config, configPath string) error {
	logPath := strings.TrimSpace(configuration.Scanner.LogFile)
	if logPath == "" {
		return nil
	}
	if configPath != "" {
		same, err := sameFile(logPath, configPath)
		if err != nil {
			return fmt.Errorf("compare log file with config path: %w", err)
		}
		if same {
			return errors.New("scanner.log_file must not overwrite the active configuration file")
		}
	}

	reportDestination := strings.TrimSpace(configuration.Report.Destination)
	if !configuration.Report.Enabled || reportDestination == report.DestinationStdout ||
		reportDestination == report.DestinationStderr {
		return nil
	}
	same, err := sameFile(logPath, reportDestination)
	if err != nil {
		return fmt.Errorf("compare log file with report destination: %w", err)
	}
	if same {
		return errors.New("scanner.log_file and report.destination must be different files")
	}
	return nil
}

func wrapLogCloseError(path string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("close log file %q: %w", path, err)
}
