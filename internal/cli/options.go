// Package cli parses the command-line options accepted by the scanner.
package cli

import (
	"flag"
	"io"
)

// Options contains all command-line settings for a scan.
type Options struct {
	Host      string
	Workers   int
	StartPort int
	EndPort   int
	Verbosity int
}

// Parse parses scanner options from args and writes flag help to output.
func Parse(args []string, output io.Writer) (Options, error) {
	flags := flag.NewFlagSet("go_port_scanner", flag.ContinueOnError)
	flags.SetOutput(output)

	var options Options
	flags.StringVar(&options.Host, "host", "localhost", "Hostname or IP address")
	flags.IntVar(&options.Workers, "workers", 10000, "Number of concurrent workers")
	flags.IntVar(&options.StartPort, "start", 1, "Start port")
	flags.IntVar(&options.EndPort, "end", 65535, "End port")

	verbose := flags.Bool("v", false, "Enable verbose output (info)")
	moreVerbose := flags.Bool("vv", false, "Enable more verbose output (debug)")
	mostVerbose := flags.Bool("vvv", false, "Enable most verbose output (trace)")

	if err := flags.Parse(args); err != nil {
		return Options{}, err
	}

	switch {
	case *mostVerbose:
		options.Verbosity = 3
	case *moreVerbose:
		options.Verbosity = 2
	case *verbose:
		options.Verbosity = 1
	}

	return options, nil
}
