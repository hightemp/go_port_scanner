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
	maxPort                 = 65535
	defaultWorkers          = 10000
	defaultMaxTargets       = 65536
	defaultDiscoveryWorkers = 256
)

// DefaultPath is the configuration file loaded when -config is not specified.
const DefaultPath = "config.yaml"

// Verbosity controls which diagnostic messages are shown.
type Verbosity string

// ProxyStrategy controls how a proxy is selected for each connection.
type ProxyStrategy string

// DiscoveryStrategy controls how hosts are checked before their ports are scanned.
type DiscoveryStrategy string

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

	// DiscoveryStrategyNone skips host discovery even when it is enabled.
	DiscoveryStrategyNone DiscoveryStrategy = "none"
	// DiscoveryStrategyTCP checks whether any configured TCP port responds.
	DiscoveryStrategyTCP DiscoveryStrategy = "tcp"
	// DiscoveryStrategyICMP sends an ICMP echo request.
	DiscoveryStrategyICMP DiscoveryStrategy = "icmp"
	// DiscoveryStrategyICMPThenTCP tries ICMP first and falls back to TCP.
	DiscoveryStrategyICMPThenTCP DiscoveryStrategy = "icmp_then_tcp"
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
	MaxTargets  int       `yaml:"max_targets"`
	DialTimeout Duration  `yaml:"dial_timeout"`
	ScanTimeout Duration  `yaml:"scan_timeout"`
	Verbosity   Verbosity `yaml:"verbosity"`
}

// Discovery contains optional host availability checks performed before scanning.
type Discovery struct {
	Enabled  bool              `yaml:"enabled"`
	Strategy DiscoveryStrategy `yaml:"strategy"`
	Workers  int               `yaml:"workers"`
	Timeout  Duration          `yaml:"timeout"`
	TCPPorts []PortRange       `yaml:"tcp_ports"`
}

// Proxy contains optional HTTP, HTTPS, and SOCKS5 proxy pool settings.
type Proxy struct {
	Enabled               bool          `yaml:"enabled"`
	Strategy              ProxyStrategy `yaml:"strategy"`
	TLSInsecureSkipVerify bool          `yaml:"tls_insecure_skip_verify"`
	URLs                  []string      `yaml:"urls"`
}

// ProtocolProbe contains settings shared by every protocol handshake.
type ProtocolProbe struct {
	Enabled bool        `yaml:"enabled"`
	Ports   []PortRange `yaml:"ports"`
}

// Probes contains optional application-protocol handshake settings.
type Probes struct {
	Enabled               bool          `yaml:"enabled"`
	Timeout               Duration      `yaml:"timeout"`
	TLSInsecureSkipVerify bool          `yaml:"tls_insecure_skip_verify"`
	SSH                   ProtocolProbe `yaml:"ssh"`
	FTP                   ProtocolProbe `yaml:"ftp"`
	FTPSExplicit          ProtocolProbe `yaml:"ftps_explicit"`
	FTPSImplicit          ProtocolProbe `yaml:"ftps_implicit"`
	PostgreSQL            ProtocolProbe `yaml:"postgresql"`
	MySQL                 ProtocolProbe `yaml:"mysql"`
	MongoDB               ProtocolProbe `yaml:"mongodb"`
	MSSQL                 ProtocolProbe `yaml:"mssql"`
	Cassandra             ProtocolProbe `yaml:"cassandra"`
	Elasticsearch         ProtocolProbe `yaml:"elasticsearch"`
	RabbitMQ              ProtocolProbe `yaml:"rabbitmq"`
	Kafka                 ProtocolProbe `yaml:"kafka"`
	NATS                  ProtocolProbe `yaml:"nats"`
	MQTT                  ProtocolProbe `yaml:"mqtt"`
	Redis                 ProtocolProbe `yaml:"redis"`
	Memcached             ProtocolProbe `yaml:"memcached"`
	Etcd                  ProtocolProbe `yaml:"etcd"`
	RDP                   ProtocolProbe `yaml:"rdp"`
	SMB                   ProtocolProbe `yaml:"smb"`
	NetBIOS               ProtocolProbe `yaml:"netbios"`
	MSRPC                 ProtocolProbe `yaml:"msrpc"`
	Kerberos              ProtocolProbe `yaml:"kerberos"`
	LDAP                  ProtocolProbe `yaml:"ldap"`
	LDAPS                 ProtocolProbe `yaml:"ldaps"`
	WinRM                 ProtocolProbe `yaml:"winrm"`
	WinRMHTTPS            ProtocolProbe `yaml:"winrm_https"`
}

// ProbeDefinition describes one enabled protocol and its expanded ports.
type ProbeDefinition struct {
	Name  string
	Ports []int
}

// Config contains the complete scanner configuration.
type Config struct {
	Targets   []string    `yaml:"targets"`
	Ports     []PortRange `yaml:"ports"`
	Scanner   Scanner     `yaml:"scanner"`
	Discovery Discovery   `yaml:"discovery"`
	Proxy     Proxy       `yaml:"proxy"`
	Probes    Probes      `yaml:"probes"`
}

// Default returns the built-in scanner configuration.
func Default() Config {
	return Config{
		Targets: []string{"localhost"},
		Ports:   []PortRange{{Start: 1, End: maxPort}},
		Scanner: Scanner{
			Workers:     defaultWorkers,
			MaxTargets:  defaultMaxTargets,
			DialTimeout: Duration{Duration: time.Second},
			ScanTimeout: Duration{},
			Verbosity:   VerbosityQuiet,
		},
		Discovery: Discovery{
			Enabled:  false,
			Strategy: DiscoveryStrategyICMPThenTCP,
			Workers:  defaultDiscoveryWorkers,
			Timeout:  Duration{Duration: 500 * time.Millisecond},
			TCPPorts: []PortRange{
				{Start: 22, End: 22},
				{Start: 80, End: 80},
				{Start: 443, End: 443},
				{Start: 445, End: 445},
				{Start: 3389, End: 3389},
				{Start: 5985, End: 5985},
			},
		},
		Proxy: Proxy{
			Enabled:  false,
			Strategy: ProxyStrategyRoundRobin,
			URLs:     []string{},
		},
		Probes: defaultProbes(),
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
	if c.Scanner.MaxTargets < 1 {
		return errors.New("scanner.max_targets must be greater than zero")
	}
	if _, err := c.ExpandedTargets(); err != nil {
		return err
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
	if err := c.validateDiscovery(); err != nil {
		return err
	}
	if c.Probes.Timeout.Duration <= 0 {
		return errors.New("probes.timeout must be greater than zero")
	}
	for name, protocol := range c.probeProtocols() {
		if !protocol.Enabled {
			continue
		}
		if len(protocol.Ports) == 0 {
			return fmt.Errorf("probes.%s.ports must not be empty when the probe is enabled", name)
		}
		for index, portRange := range protocol.Ports {
			if portRange.Start < 1 || portRange.End > maxPort || portRange.Start > portRange.End {
				return fmt.Errorf("probes.%s.ports[%d] must be between 1 and %d", name, index, maxPort)
			}
		}
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

func (c Config) validateDiscovery() error {
	switch c.Discovery.Strategy {
	case DiscoveryStrategyNone, DiscoveryStrategyTCP, DiscoveryStrategyICMP, DiscoveryStrategyICMPThenTCP:
	default:
		return fmt.Errorf("unsupported discovery.strategy %q", c.Discovery.Strategy)
	}
	if c.Discovery.Workers < 1 {
		return errors.New("discovery.workers must be greater than zero")
	}
	if c.Discovery.Timeout.Duration <= 0 {
		return errors.New("discovery.timeout must be greater than zero")
	}
	if !c.Discovery.Enabled || c.Discovery.Strategy == DiscoveryStrategyNone ||
		c.Discovery.Strategy == DiscoveryStrategyICMP {
		return nil
	}
	if len(c.Discovery.TCPPorts) == 0 {
		return errors.New("discovery.tcp_ports must not be empty for a TCP discovery strategy")
	}
	for index, portRange := range c.Discovery.TCPPorts {
		if portRange.Start < 1 || portRange.End > maxPort || portRange.Start > portRange.End {
			return fmt.Errorf("discovery.tcp_ports[%d] must be between 1 and %d", index, maxPort)
		}
	}
	return nil
}

func defaultProbes() Probes {
	protocol := func(ports ...PortRange) ProtocolProbe {
		return ProtocolProbe{Enabled: true, Ports: ports}
	}
	single := func(port int) PortRange { return PortRange{Start: port, End: port} }

	return Probes{
		Enabled:       false,
		Timeout:       Duration{Duration: 2 * time.Second},
		SSH:           protocol(single(22)),
		FTP:           protocol(single(21)),
		FTPSExplicit:  protocol(single(21)),
		FTPSImplicit:  protocol(single(990)),
		PostgreSQL:    protocol(single(5432)),
		MySQL:         protocol(single(3306)),
		MongoDB:       protocol(single(27017)),
		MSSQL:         protocol(single(1433)),
		Cassandra:     protocol(single(9042)),
		Elasticsearch: protocol(single(9200)),
		RabbitMQ:      protocol(single(5672)),
		Kafka:         protocol(single(9092)),
		NATS:          protocol(single(4222)),
		MQTT:          protocol(single(1883)),
		Redis:         protocol(single(6379)),
		Memcached:     protocol(single(11211)),
		Etcd:          protocol(single(2379)),
		RDP:           protocol(single(3389)),
		SMB:           protocol(single(445)),
		NetBIOS:       protocol(single(139)),
		MSRPC:         protocol(single(135)),
		Kerberos:      protocol(single(88)),
		LDAP:          protocol(single(389), single(3268)),
		LDAPS:         protocol(single(636), single(3269)),
		WinRM:         protocol(single(5985)),
		WinRMHTTPS:    protocol(single(5986)),
	}
}

func (c Config) probeProtocols() map[string]ProtocolProbe {
	return map[string]ProtocolProbe{
		"ssh":           c.Probes.SSH,
		"ftp":           c.Probes.FTP,
		"ftps_explicit": c.Probes.FTPSExplicit,
		"ftps_implicit": c.Probes.FTPSImplicit,
		"postgresql":    c.Probes.PostgreSQL,
		"mysql":         c.Probes.MySQL,
		"mongodb":       c.Probes.MongoDB,
		"mssql":         c.Probes.MSSQL,
		"cassandra":     c.Probes.Cassandra,
		"elasticsearch": c.Probes.Elasticsearch,
		"rabbitmq":      c.Probes.RabbitMQ,
		"kafka":         c.Probes.Kafka,
		"nats":          c.Probes.NATS,
		"mqtt":          c.Probes.MQTT,
		"redis":         c.Probes.Redis,
		"memcached":     c.Probes.Memcached,
		"etcd":          c.Probes.Etcd,
		"rdp":           c.Probes.RDP,
		"smb":           c.Probes.SMB,
		"netbios":       c.Probes.NetBIOS,
		"msrpc":         c.Probes.MSRPC,
		"kerberos":      c.Probes.Kerberos,
		"ldap":          c.Probes.LDAP,
		"ldaps":         c.Probes.LDAPS,
		"winrm":         c.Probes.WinRM,
		"winrm_https":   c.Probes.WinRMHTTPS,
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

// ExpandedDiscoveryPorts returns unique TCP discovery ports in configured order.
func (c Config) ExpandedDiscoveryPorts() []int {
	return expandPortRanges(c.Discovery.TCPPorts)
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

// EnabledProbeDefinitions returns enabled protocol handshakes in stable order.
func (c Config) EnabledProbeDefinitions() []ProbeDefinition {
	if !c.Probes.Enabled {
		return nil
	}

	configured := []struct {
		name     string
		protocol ProtocolProbe
	}{
		{name: "ssh", protocol: c.Probes.SSH},
		{name: "ftp", protocol: c.Probes.FTP},
		{name: "ftps_explicit", protocol: c.Probes.FTPSExplicit},
		{name: "ftps_implicit", protocol: c.Probes.FTPSImplicit},
		{name: "postgresql", protocol: c.Probes.PostgreSQL},
		{name: "mysql", protocol: c.Probes.MySQL},
		{name: "mongodb", protocol: c.Probes.MongoDB},
		{name: "mssql", protocol: c.Probes.MSSQL},
		{name: "cassandra", protocol: c.Probes.Cassandra},
		{name: "elasticsearch", protocol: c.Probes.Elasticsearch},
		{name: "rabbitmq", protocol: c.Probes.RabbitMQ},
		{name: "kafka", protocol: c.Probes.Kafka},
		{name: "nats", protocol: c.Probes.NATS},
		{name: "mqtt", protocol: c.Probes.MQTT},
		{name: "redis", protocol: c.Probes.Redis},
		{name: "memcached", protocol: c.Probes.Memcached},
		{name: "etcd", protocol: c.Probes.Etcd},
		{name: "rdp", protocol: c.Probes.RDP},
		{name: "smb", protocol: c.Probes.SMB},
		{name: "netbios", protocol: c.Probes.NetBIOS},
		{name: "msrpc", protocol: c.Probes.MSRPC},
		{name: "kerberos", protocol: c.Probes.Kerberos},
		{name: "ldap", protocol: c.Probes.LDAP},
		{name: "ldaps", protocol: c.Probes.LDAPS},
		{name: "winrm", protocol: c.Probes.WinRM},
		{name: "winrm_https", protocol: c.Probes.WinRMHTTPS},
	}

	definitions := make([]ProbeDefinition, 0, len(configured))
	for _, item := range configured {
		if !item.protocol.Enabled {
			continue
		}
		definitions = append(definitions, ProbeDefinition{
			Name:  item.name,
			Ports: expandPortRanges(item.protocol.Ports),
		})
	}
	return definitions
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

func expandPortRanges(ranges []PortRange) []int {
	ports := make([]int, 0)
	seen := make(map[int]struct{})
	for _, portRange := range ranges {
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
