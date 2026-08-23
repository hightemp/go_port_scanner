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
- Optional bounded reverse DNS (PTR) lookup for IP targets.
- HTTP, HTTPS CONNECT, and SOCKS5 proxy pools.
- `round_robin`, `random`, and `least_connections` proxy selection.
- Optional protocol handshakes for remote access, databases, brokers,
  key/value stores, and Windows/Active Directory services.
- Optional `text`, `json`, `jsonl`, and `csv` reports to stdout, stderr, or a
  file, with working-only result filtering.
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
  progress_interval: 5s
  verbosity: info

discovery:
  enabled: true
  strategy: icmp_then_tcp
  workers: 256
  timeout: 500ms
  tcp_ports: [22, 80, 443, 445, 3389, 5985]

reverse_dns:
  enabled: false
  workers: 64
  timeout: 1s

report:
  enabled: false
  only_working: false
  destination: scan-report.json
  format: json
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

### Reverse DNS

Reverse DNS is disabled by default. Enable it to resolve a PTR hostname once
for each IP target before discovery and port scanning:

```yaml
reverse_dns:
  enabled: true
  workers: 64
  timeout: 1s
```

Only IPv4 and IPv6 literals are queried; entries already specified as
hostnames are skipped. Lookups use a separate bounded worker pool and apply
`reverse_dns.timeout` to each IP. The first usable PTR name is displayed
alongside the IP for open ports and is written to discovery and open-port
report records. CSV reports use the `hostname` column; JSON and JSONL use the
optional `hostname` field.

A missing or timed-out PTR response does not make the host unavailable and
does not stop the scan. At info level the scanner prints a resolved/attempted
summary; debug level also prints every successful and failed PTR lookup.
Reverse DNS uses the operating system resolver directly and is not routed
through the configured proxy pool.

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
At info level, every unavailable host is logged before it is skipped. Debug
level additionally reports DNS resolution, each ICMP/TCP discovery attempt,
its duration and error, and every ICMP-to-TCP fallback.

ICMP may be blocked by a firewall. Unprivileged ICMP is supported natively on
Linux and macOS; raw ICMP fallback may require elevated privileges and is
platform-dependent. For that reason, `icmp_then_tcp` is the recommended
strategy. If a host blocks both ICMP and every configured discovery TCP port,
it will be skipped even if another port is open; add an appropriate discovery
port or use `none` to avoid that false negative.

#### Linux ICMP permissions

First check whether the current user's group is allowed to create unprivileged
ICMP sockets:

```console
id -g
sysctl net.ipv4.ping_group_range
```

The preferred option is to allow only the current primary group. This avoids
running the entire scanner as root:

```console
scanner_gid="$(id -g)"
sudo sysctl -w "net.ipv4.ping_group_range=${scanner_gid} ${scanner_gid}"
```

To preserve the setting across reboots:

```console
scanner_gid="$(id -g)"
printf 'net.ipv4.ping_group_range = %s %s\n' "$scanner_gid" "$scanner_gid" |
  sudo tee /etc/sysctl.d/99-go-port-scanner.conf
sudo sysctl --system
```

Alternatively, grant only the raw-network capability to the built binary
(`setcap` is commonly provided by the `libcap2-bin` package):

```console
make build
sudo setcap cap_net_raw+ep ./go_port_scanner
getcap ./go_port_scanner
./go_port_scanner -vv
```

File capabilities are normally removed when the binary is rebuilt, so repeat
`setcap` after each `make build`. A one-off privileged launch is also possible:

```console
make build
sudo ./go_port_scanner -config "$PWD/config.yaml" -vv
```

Do not use `sudo make run`: it builds as root and may leave root-owned artifacts
in the repository. Prefer `ping_group_range` or `CAP_NET_RAW` instead.

When a proxy pool is enabled, TCP discovery uses the same proxy path as the
port scan. ICMP is always sent directly because HTTP and SOCKS proxies cannot
forward it.

### Reports

Final reports are optional and disabled by default:

```yaml
report:
  enabled: true
  only_working: false
  destination: reports/scan.json
  format: json
```

`report.destination` accepts:

- `stdout` for standard output;
- `stderr` for standard error;
- any other value as a file path, such as `reports/scan.csv`.

Missing parent directories are created automatically. Existing report files
are replaced only after the scan reaches report generation. The active YAML
configuration file is protected from being used as the report destination.
When a report is sent to `stdout`, regular open-port output and diagnostic logs
are redirected to `stderr`, keeping report stdout clean for pipes.

Available formats:

| Format | Contents |
| --- | --- |
| `text` | Human-readable discovery, open-port, probe, and summary lines |
| `json` | One structured document with schema version `2` |
| `jsonl` | Metadata, discovery, open-port, and summary records, one JSON object per line |
| `csv` | Normalized metadata, discovery, open-port, probe, and summary rows |

With `report.only_working: false`, every format includes requested and scanned
targets, discovery availability, open ports, connection durations, protocol
handshake results, and aggregate scan statistics. Resolved PTR hostnames are
attached to discovery and open-port records. Individual closed-port records are
intentionally not retained; their refused, timeout, unreachable, and
other-error counts are included in the summary.

Set `report.only_working: true` with any format to retain only available
discovery results, targets with an available host or open port, open TCP ports,
and successful protocol probes. Open ports remain in the report even if every
configured handshake fails because the TCP connection itself worked. Filtered
summary counters describe only the retained open ports. Scan status and a
top-level interruption error are preserved so a partial result cannot be
mistaken for a complete scan.

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
  http:
    enabled: true
    ports: [80, 8080]
  https:
    enabled: true
    ports: [443, 8443]
  socks:
    enabled: true
    ports: [1080]
  dns:
    enabled: true
    ports: [53]
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
| Web/proxies | `http`, `https`, `socks` | 80, 443, 1080 |
| DNS | `dns` | 53/TCP |
| Databases/search | `postgresql`, `mysql`, `mongodb`, `mssql`, `cassandra`, `elasticsearch` | 5432, 3306, 27017, 1433, 9042, 9200 |
| Brokers/queues | `rabbitmq`, `kafka`, `nats`, `mqtt` | 5672, 9092, 4222, 1883 |
| Key/value stores | `redis`, `memcached`, `etcd` | 6379, 11211, 2379 |
| Windows remote access | `rdp`, `smb`, `netbios`, `msrpc` | 3389, 445, 139, 135 |
| Active Directory | `kerberos`, `ldap`, `ldaps` | 88, 389/3268, 636/3269 |
| Windows management | `winrm`, `winrm_https` | 5985, 5986 |

The DNS probe uses DNS-over-TCP framing and sends a root `NS` query without
requesting recursion. It verifies the transaction ID, response flag, opcode,
question, and message length. Any structurally valid DNS response confirms the
protocol, including `REFUSED` or `SERVFAIL`; the result reports the response
code and section counts. This scanner remains TCP-only, so the probe does not
test UDP port 53.

The HTTP probe sends `HEAD /` and accepts any valid HTTP response. HTTPS first
performs a TLS handshake and then sends the same request. The `socks` switch
runs independent SOCKS5 and SOCKS4-compatible probes on separate TCP
connections. SOCKS4a servers are covered by their SOCKS4 compatibility, but the
extension is not reported separately. SOCKS5 only negotiates authentication
methods. SOCKS4 has no negotiation-only message, so its required `CONNECT`
request targets the deliberately invalid `0.0.0.0:0` endpoint rather than a
real third-party host.

MySQL handshakes also recognize MariaDB-compatible greetings. RabbitMQ uses
AMQP 0-9-1. Explicit FTPS performs `AUTH TLS`; implicit FTPS starts directly
with TLS. The probe TLS verification setting applies to HTTPS, FTPS, LDAPS, and
WinRM HTTPS.

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
TCP: 53 [dns: DNS-over-TCP response (rcode=NOERROR, answers=13, authority=0, additional=1)]
TCP: 6379 [redis: PONG]
TCP: 5432 [postgresql: failed (unexpected PostgreSQL SSL response 0x45)]
```

For multiple targets the output includes the address, for example
`TCP: 192.0.2.10:22`. With reverse DNS enabled and a PTR record found, it is
shown as `TCP: 192.0.2.10:22 (server.example)`. Info mode adds lifecycle
messages, debug mode adds timing and handshake details, and trace mode reports
every attempted and closed port.
When `scanner.progress_interval` is greater than zero, info mode periodically
prints completion percentage, checks per second, open-port count, and ETA. A
final summary breaks failed checks down into timeouts, refused connections,
unreachable networks/hosts, and other errors. Trace mode also reports the proxy
selected for each connection; use it carefully because large scans can produce
millions of log lines.

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
internal/report/      text, JSON, JSONL, CSV, and result filtering
internal/reversedns/  optional bounded PTR hostname lookups
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
