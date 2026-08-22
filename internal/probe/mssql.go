package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	tdsPreloginPacket = 0x12
	tdsReplyPacket    = 0x04
)

type mssqlProbe struct{}

func (mssqlProbe) Name() string { return "mssql" }

func (mssqlProbe) Probe(_ context.Context, connection net.Conn, _ Target) (string, error) {
	request := []byte{
		tdsPreloginPacket, 0x01, 0x00, 0x1a, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x0b, 0x00, 0x06,
		0x01, 0x00, 0x11, 0x00, 0x01,
		0xff,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00,
	}
	if err := writeAll(connection, request); err != nil {
		return "", fmt.Errorf("send TDS PRELOGIN: %w", err)
	}

	header := make([]byte, 8)
	if _, err := io.ReadFull(connection, header); err != nil {
		return "", fmt.Errorf("read TDS PRELOGIN header: %w", err)
	}
	length := int(binary.BigEndian.Uint16(header[2:4]))
	if header[0] != tdsReplyPacket {
		return "", fmt.Errorf("unexpected TDS packet type 0x%02x", header[0])
	}
	if length < len(header) {
		return "", fmt.Errorf("invalid TDS packet length %d", length)
	}
	return "TDS PRELOGIN response", nil
}
