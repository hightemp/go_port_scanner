package probe

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
)

type memcachedProbe struct{}

func (memcachedProbe) Name() string { return "memcached" }

func (memcachedProbe) Probe(_ context.Context, connection net.Conn, _ Target) (string, error) {
	if err := writeAll(connection, []byte("version\r\n")); err != nil {
		return "", fmt.Errorf("send memcached version: %w", err)
	}
	line, err := readLine(bufio.NewReader(connection), maxTextLine)
	if err != nil {
		return "", fmt.Errorf("read memcached version: %w", err)
	}
	if !strings.HasPrefix(line, "VERSION ") {
		return "", fmt.Errorf("unexpected memcached response %q", cleanDetail(line))
	}
	return cleanDetail(strings.TrimPrefix(line, "VERSION ")), nil
}
