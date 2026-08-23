package main

import (
	"fmt"
	"io"
	"runtime/debug"
	"strings"

	"github.com/hightemp/go_port_scanner"
)

const (
	applicationName    = "go_port_scanner"
	developmentVersion = "dev"
)

// version is replaced at link time by Makefile and release builds.
var version = developmentVersion

func writeVersion(writer io.Writer) error {
	if _, err := fmt.Fprintf(writer, "%s %s\n", applicationName, currentVersion()); err != nil {
		return fmt.Errorf("write version: %w", err)
	}
	return nil
}

func currentVersion() string {
	if linkedVersion := normalizeVersion(version); linkedVersion != "" && linkedVersion != developmentVersion {
		return linkedVersion
	}
	if embeddedVersion := normalizeVersion(portscanner.Version()); embeddedVersion != "" {
		return embeddedVersion
	}
	if buildInformation, available := debug.ReadBuildInfo(); available {
		moduleVersion := normalizeVersion(buildInformation.Main.Version)
		if moduleVersion != "" && moduleVersion != "(devel)" {
			return moduleVersion
		}
	}
	return developmentVersion
}

func normalizeVersion(value string) string {
	value = strings.TrimSpace(value)
	return strings.TrimPrefix(value, "v")
}
