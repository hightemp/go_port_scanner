package probe

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
)

type sshProbe struct{}

func (sshProbe) Name() string { return "ssh" }

func (sshProbe) Probe(_ context.Context, connection net.Conn, _ Target) (string, error) {
	reader := bufio.NewReaderSize(connection, 256)
	for range 50 {
		line, err := readLine(reader, 255)
		if err != nil {
			return "", fmt.Errorf("read SSH identification: %w", err)
		}
		if strings.HasPrefix(line, "SSH-") {
			parts := strings.SplitN(line, "-", 3)
			if len(parts) != 3 || parts[1] == "" || parts[2] == "" {
				return "", fmt.Errorf("invalid SSH identification %q", cleanDetail(line))
			}
			return cleanDetail(line), nil
		}
	}
	return "", fmt.Errorf("SSH identification not found")
}
