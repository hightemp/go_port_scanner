// Package cli parses the command-line options accepted by the scanner.
package cli

import (
	"flag"
	"io"
	"time"

	"github.com/hightemp/go_port_scanner/internal/config"
)

// Options contains the config path and explicitly supplied CLI overrides.
type Options struct {
	ConfigPath  string
	Host        *string
	Workers     *int
	StartPort   *int
	EndPort     *int
	DialTimeout *time.Duration
	ScanTimeout *time.Duration
	Verbosity   *int
}

// Parse parses scanner options from args and writes flag help to output.
func Parse(args []string, output io.Writer) (Options, error) {
	flags := flag.NewFlagSet("go_port_scanner", flag.ContinueOnError)
	flags.SetOutput(output)

	configPath := flags.String("config", config.DefaultPath, "Path to YAML config (empty uses built-in defaults)")
	host := flags.String("host", "localhost", "Override config targets with one hostname, IP address, CIDR, or IP range")
	workers := flags.Int("workers", 10000, "Override number of concurrent workers")
	startPort := flags.Int("start", 1, "Override start port")
	endPort := flags.Int("end", 65535, "Override end port")
	dialTimeout := flags.Duration("timeout", time.Second, "Override per-connection timeout")
	scanTimeout := flags.Duration("scan-timeout", 0, "Override timeout for the whole scan (0 disables)")

	verbose := flags.Bool("v", false, "Enable verbose output (info)")
	moreVerbose := flags.Bool("vv", false, "Enable more verbose output (debug)")
	mostVerbose := flags.Bool("vvv", false, "Enable most verbose output (trace)")

	if err := flags.Parse(args); err != nil {
		return Options{}, err
	}

	options := Options{ConfigPath: *configPath}
	visited := make(map[string]bool)
	flags.Visit(func(current *flag.Flag) {
		visited[current.Name] = true
	})

	if visited["host"] {
		options.Host = host
	}
	if visited["workers"] {
		options.Workers = workers
	}
	if visited["start"] || visited["end"] {
		options.StartPort = startPort
		options.EndPort = endPort
	}
	if visited["timeout"] {
		options.DialTimeout = dialTimeout
	}
	if visited["scan-timeout"] {
		options.ScanTimeout = scanTimeout
	}

	verbosity := 0
	switch {
	case *mostVerbose:
		verbosity = 3
	case *moreVerbose:
		verbosity = 2
	case *verbose:
		verbosity = 1
	}
	if visited["v"] || visited["vv"] || visited["vvv"] {
		options.Verbosity = &verbosity
	}

	return options, nil
}
