// Package config loads and validates scanner settings from YAML files.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	maxPort        = 65535
	defaultWorkers = 10000
)

// DefaultPath is the configuration file loaded when -config is not specified.
const DefaultPath = "config.yaml"

// Verbosity controls which diagnostic messages are shown.
type Verbosity string

// ProxyStrategy controls how a proxy is selected for each connection.
type ProxyStrategy string

const (
	// VerbosityQuiet only prints open ports.
	VerbosityQuiet Verbosity = "quiet"
	// VerbosityInfo adds scan lifecycle messages.
	VerbosityInfo Verbosity = "info"
	// VerbosityDebug adds worker and connection details.
	VerbosityDebug Verbosity = "debug"
	// VerbosityTrace adds an event for every checked port.
	VerbosityTrace Verbosity = "trace"

	// ProxyStrategyRoundRobin selects proxies sequentially and wraps around.
	ProxyStrategyRoundRobin ProxyStrategy = "round_robin"
	// ProxyStrategyRandom selects a random proxy for every connection.
	ProxyStrategyRandom ProxyStrategy = "random"
	// ProxyStrategyLeastConnections selects the proxy with the fewest active connections.
	ProxyStrategyLeastConnections ProxyStrategy = "least_connections"
)

// PortRange describes an inclusive TCP port range.
type PortRange struct {
	Start int
	End   int
}

// UnmarshalYAML decodes a single port or a range such as 8000-8010.
func (r *PortRange) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return errors.New("port must be a number or range")
	}

	parsed, err := ParsePortRange(node.Value)
	if err != nil {
		return err
	}
	*r = parsed
	return nil
}

// ParsePortRange parses a single port or an inclusive start-end range.
func ParsePortRange(value string) (PortRange, error) {
	parts := strings.Split(value, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return PortRange{}, fmt.Errorf("invalid port range %q", value)
	}

	start, err := parsePort(parts[0])
	if err != nil {
		return PortRange{}, fmt.Errorf("invalid port range %q: %w", value, err)
	}
	end := start
	if len(parts) == 2 {
		end, err = parsePort(parts[1])
		if err != nil {
			return PortRange{}, fmt.Errorf("invalid port range %q: %w", value, err)
		}
	}
	if start > end {
		return PortRange{}, fmt.Errorf("invalid port range %q: start is greater than end", value)
	}

	return PortRange{Start: start, End: end}, nil
}

// Duration is a YAML duration represented using time.ParseDuration syntax.
type Duration struct {
	time.Duration
}

// UnmarshalYAML decodes values such as 500ms, 1s, or 2m.
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return errors.New("duration must be a string")
	}

	value, err := time.ParseDuration(node.Value)
	if err != nil {
		return fmt.Errorf("parse duration %q: %w", node.Value, err)
	}
	d.Duration = value
	return nil
}

// Scanner contains worker, timeout, and output settings.
type Scanner struct {
	Workers     int       `yaml:"workers"`
	DialTimeout Duration  `yaml:"dial_timeout"`
	ScanTimeout Duration  `yaml:"scan_timeout"`
	Verbosity   Verbosity `yaml:"verbosity"`
}

// Proxy contains optional HTTP, HTTPS, and SOCKS5 proxy pool settings.
type Proxy struct {
	Enabled               bool          `yaml:"enabled"`
	Strategy              ProxyStrategy `yaml:"strategy"`
	TLSInsecureSkipVerify bool          `yaml:"tls_insecure_skip_verify"`
	URLs                  []string      `yaml:"urls"`
}

// Config contains the complete scanner configuration.
type Config struct {
	Targets []string    `yaml:"targets"`
	Ports   []PortRange `yaml:"ports"`
	Scanner Scanner     `yaml:"scanner"`
	Proxy   Proxy       `yaml:"proxy"`
}

// Default returns the built-in scanner configuration.
func Default() Config {
	return Config{
		Targets: []string{"localhost"},
		Ports:   []PortRange{{Start: 1, End: maxPort}},
		Scanner: Scanner{
			Workers:     defaultWorkers,
			DialTimeout: Duration{Duration: time.Second},
			ScanTimeout: Duration{},
			Verbosity:   VerbosityQuiet,
		},
		Proxy: Proxy{
			Enabled:  false,
			Strategy: ProxyStrategyRoundRobin,
			URLs:     []string{},
		},
	}
}

// Load reads a YAML configuration file over the built-in defaults.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config %q: %w", path, err)
	}

	loaded, err := Decode(bytes.NewReader(data))
	if err != nil {
		return Config{}, fmt.Errorf("decode config %q: %w", path, err)
	}
	return loaded, nil
}

// Decode decodes one YAML document over the built-in defaults.
func Decode(reader io.Reader) (Config, error) {
	loaded := Default()
	decoder := yaml.NewDecoder(reader)
	decoder.KnownFields(true)

	if err := decoder.Decode(&loaded); errors.Is(err, io.EOF) {
		return loaded, nil
	} else if err != nil {
		return Config{}, fmt.Errorf("decode YAML: %w", err)
	}

	var extra any
	err := decoder.Decode(&extra)
	if !errors.Is(err, io.EOF) {
		if err != nil {
			return Config{}, fmt.Errorf("decode trailing YAML: %w", err)
		}
		return Config{}, errors.New("only one YAML document is allowed")
	}

	if err := loaded.Validate(); err != nil {
		return Config{}, err
	}
	return loaded, nil
}

// Validate verifies all targets, ranges, scanner settings, and proxy settings.
func (c Config) Validate() error {
	if len(c.Targets) == 0 {
		return errors.New("targets must not be empty")
	}
	for index, target := range c.Targets {
		if strings.TrimSpace(target) == "" {
			return fmt.Errorf("targets[%d] must not be empty", index)
		}
	}
	if len(c.Ports) == 0 {
		return errors.New("ports must not be empty")
	}
	for index, portRange := range c.Ports {
		if portRange.Start < 1 || portRange.End > maxPort || portRange.Start > portRange.End {
			return fmt.Errorf("ports[%d] must be between 1 and %d", index, maxPort)
		}
	}
	if c.Scanner.Workers < 1 {
		return errors.New("scanner.workers must be greater than zero")
	}
	if c.Scanner.DialTimeout.Duration <= 0 {
		return errors.New("scanner.dial_timeout must be greater than zero")
	}
	if c.Scanner.ScanTimeout.Duration < 0 {
		return errors.New("scanner.scan_timeout must not be negative")
	}
	if c.Proxy.Enabled && len(c.Proxy.URLs) == 0 {
		return errors.New("proxy.urls must not be empty when proxy is enabled")
	}
	for index, proxyURL := range c.Proxy.URLs {
		if strings.TrimSpace(proxyURL) == "" {
			return fmt.Errorf("proxy.urls[%d] must not be empty", index)
		}
	}
	switch c.Proxy.Strategy {
	case ProxyStrategyRoundRobin, ProxyStrategyRandom, ProxyStrategyLeastConnections:
	default:
		return fmt.Errorf("unsupported proxy.strategy %q", c.Proxy.Strategy)
	}
	switch c.Scanner.Verbosity {
	case VerbosityQuiet, VerbosityInfo, VerbosityDebug, VerbosityTrace:
		return nil
	default:
		return fmt.Errorf("unsupported scanner.verbosity %q", c.Scanner.Verbosity)
	}
}

// ExpandedPorts returns unique ports from all configured ranges in their configured order.
func (c Config) ExpandedPorts() []int {
	portCount := 0
	for _, portRange := range c.Ports {
		portCount += portRange.End - portRange.Start + 1
	}

	ports := make([]int, 0, portCount)
	seen := make(map[int]struct{}, portCount)
	for _, portRange := range c.Ports {
		for port := portRange.Start; port <= portRange.End; port++ {
			if _, exists := seen[port]; exists {
				continue
			}
			seen[port] = struct{}{}
			ports = append(ports, port)
		}
	}
	return ports
}

// VerbosityLevel returns the numeric logging level for the configuration.
func (c Config) VerbosityLevel() int {
	switch c.Scanner.Verbosity {
	case VerbosityInfo:
		return 1
	case VerbosityDebug:
		return 2
	case VerbosityTrace:
		return 3
	default:
		return 0
	}
}

func parsePort(value string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("parse port: %w", err)
	}
	if port < 1 || port > maxPort {
		return 0, fmt.Errorf("port must be between 1 and %d", maxPort)
	}
	return port, nil
}
