// Package portscanner exposes source-level build metadata shared by scanner commands.
package portscanner

import (
	_ "embed"
	"strings"
)

//go:embed VERSION
var versionFile string

// Version returns the normalized version stored in the repository VERSION file.
func Version() string {
	return strings.TrimPrefix(strings.TrimSpace(versionFile), "v")
}
