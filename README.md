# Go Port Scanner

[![Release](https://github.com/hightemp/go_port_scanner/actions/workflows/release.yml/badge.svg)](https://github.com/hightemp/go_port_scanner/actions/workflows/release.yml)
[![Latest release](https://img.shields.io/github/v/release/hightemp/go_port_scanner?sort=semver)](https://github.com/hightemp/go_port_scanner/releases/latest)
[![Go version](https://img.shields.io/badge/Go-1.23-00ADD8?logo=go&logoColor=white)](https://go.dev/dl/)
[![Go Report Card](https://goreportcard.com/badge/github.com/hightemp/go_port_scanner)](https://goreportcard.com/report/github.com/hightemp/go_port_scanner)
[![Go Reference](https://pkg.go.dev/badge/github.com/hightemp/go_port_scanner.svg)](https://pkg.go.dev/github.com/hightemp/go_port_scanner)
[![](https://asdertasd.site/counter/go_port_scanner)](https://asdertasd.site/counter/go_port_scanner)

A concurrent TCP port scanner with YAML configuration, optional proxy rotation,
and lightweight application-protocol handshakes. It supports multiple targets,
IPv4/IPv6 addresses, CIDR subnets, IP ranges, hostnames, individual ports, and
inclusive port ranges.

> Use this tool only against systems you own or are explicitly authorized to
> test.

## Features

- Concurrent TCP scanning with a configurable worker pool.
- Per-connection and whole-scan timeouts.
- Multiple hostnames, individual IPs, CIDR subnets, and inclusive IP ranges.
- Deduplication of overlapping target specifications and port ranges.
- Optional parallel host discovery using TCP, ICMP, or ICMP with TCP fallback.
- HTTP, HTTPS CONNECT, and SOCKS5 proxy pools.
- `round_robin`, `random`, and `least_connections` proxy selection.
- Optional protocol handshakes for remote access, databases, brokers,
  key/value stores, and Windows/Active Directory services.
- Quiet, info, debug, and trace output levels.
- Static release binaries for Linux, macOS, and Windows on amd64 and arm64.

## Requirements

- Go 1.23 or newer for building from source.
- `make` for the provided build shortcuts (optional).

## Installation

Download a ready-to-run binary from
[GitHub Releases](https://github.com/hightemp/go_port_scanner/releases), or
build from source:

```console
git clone https://github.com/hightemp/go_port_scanner.git
cd go_port_scanner
make build
```

`make build` creates `./go_port_scanner`. A static binary can be built with
`make build_static`. You can also install the command directly:

```console
go install github.com/hightemp/go_port_scanner/cmd/go-port-scanner@latest
```

The `go install` binary is named `go-port-scanner`.

## Quick start

Run a scan without a YAML file by passing an empty config path and explicit
overrides:

```console
./go_port_scanner -config "" -host 127.0.0.1 -start 1 -end 1024 -workers 500
```

For regular use, copy and edit the tracked example:

```console
cp config.example.yaml config.yaml
make build
./go_port_scanner
```

`config.yaml` is ignored by Git and is loaded by default. If it does not exist,
either create it, specify another file with `-config`, or use `-config ""` to
load the built-in defaults.

## Command-line options

| Option | Description | Default |
| --- | --- | --- |
| `-config PATH` | YAML configuration path; an empty value uses built-in defaults | `config.yaml` |
| `-host TARGET` | Replace all configured targets with one hostname, IP, CIDR, or IP range | `localhost` |
| `-start PORT` | Replace the configured port list with a range starting here | `1` |
| `-end PORT` | Replace the configured port list with a range ending here | `65535` |
| `-workers N` | Number of concurrent workers | `10000` |
| `-timeout DURATION` | Per-connection timeout | `1s` |
| `-scan-timeout DURATION` | Timeout for the entire scan; `0` disables it | `0s` |
| `-v` | Info output | off |
| `-vv` | Debug output | off |
| `-vvv` | Trace every checked and closed port | off |

Only explicitly supplied flags override YAML values. Supplying either `-start`
or `-end` replaces the YAML port list; the omitted boundary uses its CLI
default. Run `./go_port_scanner -h` for generated help.

## Configuration

The complete, documented configuration is available in
[`config.example.yaml`](config.example.yaml). Unknown YAML fields and invalid
values are rejected at startup.

```yaml
targets:
  - 127.0.0.1
  - example.com
  - 192.168.1.0/24
  - 192.168.2.10-192.168.2.50
  - 2001:db8::/126

ports:
  - 22
  - 80-90
  - 443

scanner:
  workers: 500
  max_targets: 65536
  dial_timeout: 750ms
  scan_timeout: 2m
  verbosity: info

discovery:
  enabled: true
  strategy: icmp_then_tcp
  workers: 256
  timeout: 500ms
  tcp_ports: [22, 80, 443, 445, 3389, 5985]
```

Each `targets` entry may use one of these forms:

- a hostname: `example.com`;
- one IPv4 or IPv6 address: `192.168.1.10` or `2001:db8::1`;
- a CIDR subnet: `192.168.1.0/24` or `2001:db8::/126`;
- an inclusive range: `192.168.1.10-192.168.1.50` or
  `2001:db8::1-2001:db8::ff`;
- an IPv4 range with a shortened last octet: `192.168.1.10-50`.

All addresses in a CIDR are scanned, including the IPv4 network and broadcast
addresses. Overlapping subnets, ranges, and individual addresses are
deduplicated in their configured order. `scanner.max_targets` limits the number
of unique targets after expansion and defaults to `65536`, preventing an
accidentally broad subnet such as an IPv6 `/64` from exhausting memory. Narrow
the target list or raise the limit explicitly when a larger scan is intended.

Ports accept individual values and inclusive ranges. Overlapping port ranges
are also deduplicated in their configured order. The effective worker count
never exceeds the total number of target/port checks.

### Host discovery

Host discovery is disabled by default. When enabled, it filters unavailable
targets before the full port scan begins:

```yaml
discovery:
  enabled: true
  strategy: icmp_then_tcp
  workers: 256
  timeout: 500ms
  tcp_ports: [22, 80, 443, 445, 3389, 5985]
```

Available strategies:

| Strategy | Behavior |
| --- | --- |
| `none` | Do not probe or filter targets, even when discovery is enabled |
| `tcp` | Try the configured TCP ports; a connection or explicit refusal marks the host reachable |
| `icmp` | Require an ICMP echo reply |
| `icmp_then_tcp` | Try ICMP first, then fall back to the configured TCP ports |

`discovery.timeout` applies to each ICMP request or TCP port attempt. Discovery
uses its own bounded worker pool and preserves the configured target order.
The TCP discovery ports do not need to be present in the main `ports` list.

ICMP may be blocked by a firewall. Unprivileged ICMP is supported natively on
Linux and macOS; raw ICMP fallback may require elevated privileges and is
platform-dependent. For that reason, `icmp_then_tcp` is the recommended
strategy. If a host blocks both ICMP and every configured discovery TCP port,
it will be skipped even if another port is open; add an appropriate discovery
port or use `none` to avoid that false negative.

When a proxy pool is enabled, TCP discovery uses the same proxy path as the
port scan. ICMP is always sent directly because HTTP and SOCKS proxies cannot
forward it.

### Proxy pool

The proxy pool is disabled by default. When enabled, each connection selects a
proxy according to the configured strategy:

```yaml
proxy:
  enabled: true
  strategy: round_robin
  tls_insecure_skip_verify: false
  urls:
    - http://user:password@127.0.0.1:8080
    - https://proxy.example.com:8443
    - socks5://user:password@127.0.0.1:1080
```

Supported URL schemes are `http`, `https`, `socks5`, `socks5h`, and `socks`
(the last three use SOCKS5). HTTP and HTTPS proxies use CONNECT. HTTP Basic and
SOCKS5 username/password authentication can be embedded in the URL.

The scanner does not silently fall back to a direct connection when a proxy
fails. Set `proxy.tls_insecure_skip_verify: true` only when you intentionally
accept an unverified HTTPS proxy certificate.

### Protocol handshakes

Protocol checks run after TCP connect and are globally disabled by default:

```yaml
probes:
  enabled: true
  timeout: 2s
  tls_insecure_skip_verify: false

  ssh:
    enabled: true
    ports: [22, 2200-2210]
  postgresql:
    enabled: true
    ports: [5432]
  redis:
    enabled: false
    ports: [6379]
```

The example configuration has every per-protocol switch enabled. Therefore,
changing only `probes.enabled` to `true` enables every listed probe; disable
unwanted protocol entries individually. A probe runs only when its configured
port is also present in the top-level `ports` scan list.

| Category | YAML key | Default port(s) |
| --- | --- | --- |
| Remote access | `ssh` | 22 |
| FTP | `ftp`, `ftps_explicit`, `ftps_implicit` | 21, 21, 990 |
| Databases/search | `postgresql`, `mysql`, `mongodb`, `mssql`, `cassandra`, `elasticsearch` | 5432, 3306, 27017, 1433, 9042, 9200 |
| Brokers/queues | `rabbitmq`, `kafka`, `nats`, `mqtt` | 5672, 9092, 4222, 1883 |
| Key/value stores | `redis`, `memcached`, `etcd` | 6379, 11211, 2379 |
| Windows remote access | `rdp`, `smb`, `netbios`, `msrpc` | 3389, 445, 139, 135 |
| Active Directory | `kerberos`, `ldap`, `ldaps` | 88, 389/3268, 636/3269 |
| Windows management | `winrm`, `winrm_https` | 5985, 5986 |

MySQL handshakes also recognize MariaDB-compatible greetings. RabbitMQ uses
AMQP 0-9-1. Explicit FTPS performs `AUTH TLS`; implicit FTPS starts directly
with TLS. The probe TLS verification setting applies to FTPS, LDAPS, and WinRM
HTTPS.

If multiple probes share a port (for example, FTP and explicit FTPS on port
21), each probe gets a new connection. When proxies are enabled, this also
causes a new proxy selection. A failed handshake does not change the successful
TCP result: the port is still reported as open with a per-protocol error.

Windows dynamic RPC ports (`49152-65535`) remain regular TCP scan targets and
do not automatically receive the Endpoint Mapper handshake because services on
those ports expose different RPC interfaces.

## Output

Quiet mode prints open ports. Successful and failed handshakes are appended to
the same line:

```text
TCP: 22 [ssh: SSH-2.0-OpenSSH_9.9]
TCP: 6379 [redis: PONG]
TCP: 5432 [postgresql: failed (unexpected PostgreSQL SSL response 0x45)]
```

For multiple targets the output includes the address, for example
`TCP: 192.0.2.10:22`. Info mode adds lifecycle messages, debug mode adds timing
and handshake details, and trace mode reports every attempted and closed port.

## Development

```console
go test -race ./...
go vet ./...
golangci-lint run
```

Useful Make targets:

| Target | Action |
| --- | --- |
| `make build` | Build `go_port_scanner` |
| `make build_static` | Build `go_port_scanner_static` with CGO disabled |
| `make run` | Build and run using the default configuration |
| `make clean` | Remove the regular build artifact |
| `make release` | Test, commit, tag, and push a release |

Project layout:

```text
cmd/go-port-scanner/  CLI entry point, output, and application wiring
internal/cli/         command-line parsing
internal/config/      YAML defaults, loading, and validation
internal/discovery/   optional TCP and ICMP host discovery
internal/logging/     verbosity-aware output
internal/probe/       modular application-protocol handshakes
internal/proxypool/   proxy parsing, selection, and dialing
internal/scanner/     concurrent TCP scanner
```

## Release

Set a semantic version in `VERSION`, ensure all intended changes are present,
then run:

```console
make release
```

> **Warning:** `make release` stages and commits all current changes, forcibly
> updates the annotated version tag, and force-pushes both the current branch
> and tag to `origin` (or `REMOTE=<name>`). Review the worktree before running
> it.

The target runs `go test -race ./...`, creates a `release: v<version>` commit,
and pushes the tag. The Release workflow verifies that the tag matches
`VERSION`, then publishes Linux, macOS, and Windows binaries for amd64/arm64,
`config.example.yaml`, and SHA-256 checksums.
