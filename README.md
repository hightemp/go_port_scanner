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
