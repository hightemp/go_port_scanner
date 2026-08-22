package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

type rabbitmqProbe struct{}

func (rabbitmqProbe) Name() string { return "rabbitmq" }

func (rabbitmqProbe) Probe(_ context.Context, connection net.Conn, _ Target) (string, error) {
	if err := writeAll(connection, []byte{'A', 'M', 'Q', 'P', 0, 0, 9, 1}); err != nil {
		return "", fmt.Errorf("send AMQP protocol header: %w", err)
	}

	header := make([]byte, 7)
	if _, err := io.ReadFull(connection, header); err != nil {
		return "", fmt.Errorf("read AMQP frame header: %w", err)
	}
	payloadLength := binary.BigEndian.Uint32(header[3:7])
	if header[0] != 1 || header[1] != 0 || header[2] != 0 || payloadLength < 4 || payloadLength > 1<<20 {
		return "", fmt.Errorf("invalid AMQP Connection.Start frame")
	}
	method := make([]byte, 4)
	if _, err := io.ReadFull(connection, method); err != nil {
		return "", fmt.Errorf("read AMQP Connection.Start method: %w", err)
	}
	if binary.BigEndian.Uint16(method[:2]) != 10 || binary.BigEndian.Uint16(method[2:]) != 10 {
		return "", fmt.Errorf("unexpected AMQP method %x", method)
	}
	return "AMQP 0-9-1 Connection.Start", nil
}
