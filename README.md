# go_port_scanner

This is a simple TCP port scanner written in Go. 

```console
$ make build
```

## Configuration

Create a local configuration from the tracked example. `config.yaml` is ignored
by Git and loaded by the scanner by default:

```console
$ cp config.example.yaml config.yaml
```

Targets can be IPv4 addresses, IPv6 addresses, or hostnames. Ports can be
individual numbers or inclusive ranges:

```yaml
targets:
  - 127.0.0.1
  - example.com

ports:
  - 22
  - 80-90
  - 443

scanner:
  workers: 500
  dial_timeout: 750ms
  scan_timeout: 2m
  verbosity: info
```

Use another file with `-config path/to/config.yaml`. An empty `-config ""`
uses the built-in defaults. Explicit `-host`, `-start`, `-end`, `-workers`,
`-timeout`, `-scan-timeout`, and verbosity flags override YAML values.

### Proxy pool

The proxy pool is disabled by default. When enabled, every target/port
connection selects a proxy according to the configured strategy; the scanner
never falls back to a direct connection if a proxy fails.

```yaml
proxy:
  enabled: true
  strategy: round_robin
  tls_insecure_skip_verify: false
  urls:
    - http://user:password@127.0.0.1:8080
    - https://proxy.example.com:8443
    - socks5://127.0.0.1:1080
```

Supported strategies are:

- `round_robin` — cycles through proxies in their configured order.
- `random` — selects a random proxy for every connection.
- `least_connections` — selects the proxy with the fewest active connections.

Supported schemes are `http`, `https`, `socks5`, `socks5h`, and `socks` (the
last three use SOCKS5). HTTP Basic and SOCKS5 username/password authentication
can be supplied in the URL. HTTP and HTTPS proxies use the CONNECT method. Set
`tls_insecure_skip_verify: true` only for an HTTPS proxy whose certificate you
have explicitly chosen not to verify.

### Protocol handshakes

Protocol checks are disabled by default. They run after TCP connect, use the
same direct or proxy dialer, and have both a global switch and a switch for
every protocol:

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

The full list and default ports are in `config.example.yaml`. Implemented
checks are:

- SSH.
- FTP, explicit FTPS (`AUTH TLS`), and implicit FTPS.
- PostgreSQL, MySQL/MariaDB, MongoDB, Microsoft SQL Server, Cassandra, and
  Elasticsearch.
- RabbitMQ/AMQP 0-9-1, Kafka, NATS, and MQTT.
- Redis, Memcached, and etcd.

When several enabled checks use the same port, each check opens its own
connection. Consequently, a proxy is selected again for every protocol
handshake. A failed handshake does not hide the successful TCP result: output
shows the port as open and reports each protocol result separately.

## Release

Update `VERSION`, then run:

```console
$ make release
```

The command runs the tests, commits all current changes as `release: v<version>`,
force-updates the annotated version tag, and force-pushes both the current branch
and the tag to `origin`. Pushing the tag starts GitHub Actions, which publishes
Linux, macOS, and Windows binaries with SHA-256 checksums.

```console
$ ./go_port_scanner -host 192.168.31.142 -workers 10000 
TCP: 22
TCP: 5000
TCP: 9090
$ ./go_port_scanner -host proxyapi.ru -workers 10 -start 1 -end 80
TCP: 80
$ ./go_port_scanner -host proxyapi.ru -workers 10 -start 1 -end 443
TCP: 80
TCP: 443
```
