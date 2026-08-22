# go_port_scanner

This is a simple TCP port scanner written in Go. 

```console
$ make build
```

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
