package probe

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

type natsProbe struct{}

func (natsProbe) Name() string { return "nats" }

func (natsProbe) Probe(_ context.Context, connection net.Conn, _ Target) (string, error) {
	line, err := readLine(bufio.NewReader(connection), maxTextLine)
	if err != nil {
		return "", fmt.Errorf("read NATS INFO: %w", err)
	}
	if !strings.HasPrefix(line, "INFO ") {
		return "", fmt.Errorf("unexpected NATS greeting %q", cleanDetail(line))
	}
	var information struct {
		Version    string `json:"version"`
		ServerName string `json:"server_name"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(line, "INFO "))), &information); err != nil {
		return "", fmt.Errorf("decode NATS INFO: %w", err)
	}
	detail := "version " + information.Version
	if information.ServerName != "" {
		detail += ", server " + information.ServerName
	}
	return cleanDetail(detail), nil
}
