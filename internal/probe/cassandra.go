package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

type cassandraProbe struct{}

func (cassandraProbe) Name() string { return "cassandra" }

func (cassandraProbe) Probe(_ context.Context, connection net.Conn, _ Target) (string, error) {
	request := []byte{0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00}
	if err := writeAll(connection, request); err != nil {
		return "", fmt.Errorf("send Cassandra OPTIONS: %w", err)
	}

	header := make([]byte, 9)
	if _, err := io.ReadFull(connection, header); err != nil {
		return "", fmt.Errorf("read Cassandra frame header: %w", err)
	}
	length := binary.BigEndian.Uint32(header[5:9])
	if header[0] != 0x84 {
		return "", fmt.Errorf("unexpected Cassandra protocol version 0x%02x", header[0])
	}
	if header[2] != 0 || header[3] != 0 {
		return "", fmt.Errorf("unexpected Cassandra stream id %d", int16(binary.BigEndian.Uint16(header[2:4])))
	}
	if header[4] != 0x06 && header[4] != 0x00 {
		return "", fmt.Errorf("unexpected Cassandra opcode 0x%02x", header[4])
	}
	if length > 256<<20 {
		return "", fmt.Errorf("invalid Cassandra frame length %d", length)
	}
	if header[4] == 0x00 {
		return "native protocol v4 error response", nil
	}
	return "native protocol v4 SUPPORTED response", nil
}
