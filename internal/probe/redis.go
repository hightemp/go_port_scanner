package probe

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
)

type redisProbe struct{}

func (redisProbe) Name() string { return "redis" }

func (redisProbe) Probe(_ context.Context, connection net.Conn, _ Target) (string, error) {
	if err := writeAll(connection, []byte("*1\r\n$4\r\nPING\r\n")); err != nil {
		return "", fmt.Errorf("send Redis PING: %w", err)
	}
	line, err := readLine(bufio.NewReader(connection), maxTextLine)
	if err != nil {
		return "", fmt.Errorf("read Redis response: %w", err)
	}
	if line == "+PONG" {
		return "PONG", nil
	}
	if strings.HasPrefix(line, "-NOAUTH") || strings.HasPrefix(line, "-DENIED") ||
		strings.HasPrefix(line, "-NOPERM") {
		return cleanDetail(strings.TrimPrefix(line, "-")), nil
	}
	return "", fmt.Errorf("unexpected Redis response %q", cleanDetail(line))
}
