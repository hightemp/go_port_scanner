package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

type postgresqlProbe struct{}

func (postgresqlProbe) Name() string { return "postgresql" }

func (postgresqlProbe) Probe(_ context.Context, connection net.Conn, _ Target) (string, error) {
	request := make([]byte, 8)
	binary.BigEndian.PutUint32(request[0:4], 8)
	binary.BigEndian.PutUint32(request[4:8], 80877103)
	if err := writeAll(connection, request); err != nil {
		return "", fmt.Errorf("send PostgreSQL SSLRequest: %w", err)
	}

	response := []byte{0}
	if _, err := io.ReadFull(connection, response); err != nil {
		return "", fmt.Errorf("read PostgreSQL SSL response: %w", err)
	}
	switch response[0] {
	case 'S':
		return "SSL supported", nil
	case 'N':
		return "SSL not supported", nil
	default:
		return "", fmt.Errorf("unexpected PostgreSQL SSL response 0x%02x", response[0])
	}
}
