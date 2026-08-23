// Package probe performs bounded application-protocol handshakes on open TCP connections.
package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// Target identifies the endpoint being probed.
type Target struct {
	Host string
	Port int
}

// Prober recognizes one application protocol on an established connection.
type Prober interface {
	Name() string
	Probe(ctx context.Context, connection net.Conn, target Target) (string, error)
}

// Definition maps a named protocol to one or more ports.
type Definition struct {
	Name  string
	Ports []int
}

// Config controls registered protocols and per-handshake timeouts.
type Config struct {
	Timeout               time.Duration
	TLSInsecureSkipVerify bool
	Definitions           []Definition
}

// Result contains the outcome of one protocol handshake.
type Result struct {
	Protocol string
	Detail   string
	Duration time.Duration
	Err      error
}

// Registry resolves and runs configured probes by port.
type Registry struct {
	timeout time.Duration
	byPort  map[int][]Prober
}

// NewRegistry constructs an immutable protocol registry.
func NewRegistry(config Config) (*Registry, error) {
	if config.Timeout <= 0 {
		return nil, errors.New("probe timeout must be greater than zero")
	}

	registry := &Registry{
		timeout: config.Timeout,
		byPort:  make(map[int][]Prober),
	}
	for _, definition := range config.Definitions {
		if len(definition.Ports) == 0 {
			return nil, fmt.Errorf("probe %q has no ports", definition.Name)
		}
		protocols, err := newProtocols(definition.Name, config.TLSInsecureSkipVerify)
		if err != nil {
			return nil, err
		}
		for _, port := range definition.Ports {
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("probe %q has invalid port %d", definition.Name, port)
			}
			registry.byPort[port] = append(registry.byPort[port], protocols...)
		}
	}
	return registry, nil
}

// ForPort returns the configured probes for port in configuration order.
func (r *Registry) ForPort(port int) []Prober {
	if r == nil {
		return nil
	}
	return r.byPort[port]
}

// Count returns the number of configured protocol-to-port mappings.
func (r *Registry) Count() int {
	if r == nil {
		return 0
	}
	count := 0
	for _, protocols := range r.byPort {
		count += len(protocols)
	}
	return count
}

// Run applies the configured deadline and executes one handshake.
func (r *Registry) Run(ctx context.Context, protocol Prober, connection net.Conn, target Target) Result {
	startedAt := time.Now()
	result := Result{Protocol: protocol.Name()}

	deadline := startedAt.Add(r.timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		result.Err = fmt.Errorf("set probe deadline: %w", err)
		result.Duration = time.Since(startedAt)
		return result
	}

	stopCancellation := context.AfterFunc(ctx, func() {
		_ = connection.SetDeadline(time.Now())
	})
	result.Detail, result.Err = protocol.Probe(ctx, connection, target)
	stopCancellation()
	_ = connection.SetDeadline(time.Time{})
	if ctx.Err() != nil {
		result.Err = ctx.Err()
	}
	result.Duration = time.Since(startedAt)
	return result
}

func newProtocols(name string, tlsInsecureSkipVerify bool) ([]Prober, error) {
	if name == "socks" {
		return []Prober{socks5Probe{}, socks4Probe{}}, nil
	}
	protocol, err := newProtocol(name, tlsInsecureSkipVerify)
	if err != nil {
		return nil, err
	}
	return []Prober{protocol}, nil
}

func newProtocol(name string, tlsInsecureSkipVerify bool) (Prober, error) {
	switch name {
	case "ssh":
		return sshProbe{}, nil
	case "ftp":
		return ftpProbe{}, nil
	case "ftps_explicit":
		return ftpsExplicitProbe{tlsInsecureSkipVerify: tlsInsecureSkipVerify}, nil
	case "ftps_implicit":
		return ftpsImplicitProbe{tlsInsecureSkipVerify: tlsInsecureSkipVerify}, nil
	case "http":
		return httpProbe{}, nil
	case "https":
		return httpsProbe{tlsInsecureSkipVerify: tlsInsecureSkipVerify}, nil
	case "postgresql":
		return postgresqlProbe{}, nil
	case "mysql":
		return mysqlProbe{}, nil
	case "mongodb":
		return mongodbProbe{}, nil
	case "mssql":
		return mssqlProbe{}, nil
	case "cassandra":
		return cassandraProbe{}, nil
	case "elasticsearch":
		return elasticsearchProbe{}, nil
	case "rabbitmq":
		return rabbitmqProbe{}, nil
	case "kafka":
		return kafkaProbe{}, nil
	case "nats":
		return natsProbe{}, nil
	case "mqtt":
		return mqttProbe{}, nil
	case "redis":
		return redisProbe{}, nil
	case "memcached":
		return memcachedProbe{}, nil
	case "etcd":
		return etcdProbe{}, nil
	case "rdp":
		return rdpProbe{}, nil
	case "smb":
		return smbProbe{}, nil
	case "netbios":
		return netbiosProbe{}, nil
	case "msrpc":
		return msrpcProbe{}, nil
	case "kerberos":
		return kerberosProbe{}, nil
	case "ldap":
		return ldapProbe{}, nil
	case "ldaps":
		return ldapsProbe{tlsInsecureSkipVerify: tlsInsecureSkipVerify}, nil
	case "winrm":
		return winrmProbe{}, nil
	case "winrm_https":
		return winrmHTTPSProbe{tlsInsecureSkipVerify: tlsInsecureSkipVerify}, nil
	default:
		return nil, fmt.Errorf("unsupported probe %q", name)
	}
}
