package probe

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const maxMySQLHandshake = 1 << 20

type mysqlProbe struct{}

func (mysqlProbe) Name() string { return "mysql" }

func (mysqlProbe) Probe(_ context.Context, connection net.Conn, _ Target) (string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(connection, header); err != nil {
		return "", fmt.Errorf("read MySQL packet header: %w", err)
	}
	length := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if length < 1 || length > maxMySQLHandshake {
		return "", fmt.Errorf("invalid MySQL handshake length %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(connection, payload); err != nil {
		return "", fmt.Errorf("read MySQL handshake: %w", err)
	}
	if payload[0] == 0xff {
		if len(payload) >= 3 {
			return fmt.Sprintf("server error %d", binary.LittleEndian.Uint16(payload[1:3])), nil
		}
		return "server error", nil
	}
	if payload[0] != 0x0a {
		return "", fmt.Errorf("unexpected MySQL protocol version %d", payload[0])
	}
	terminator := bytes.IndexByte(payload[1:], 0)
	if terminator < 0 {
		return "", fmt.Errorf("unterminated MySQL server version")
	}
	return cleanDetail(string(payload[1 : terminator+1])), nil
}
