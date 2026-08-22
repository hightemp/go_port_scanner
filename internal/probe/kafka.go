package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const kafkaCorrelationID = 1

type kafkaProbe struct{}

func (kafkaProbe) Name() string { return "kafka" }

func (kafkaProbe) Probe(_ context.Context, connection net.Conn, _ Target) (string, error) {
	clientID := []byte("go-port-scanner")
	payload := make([]byte, 10+len(clientID))
	binary.BigEndian.PutUint16(payload[0:2], 18) // ApiVersions
	binary.BigEndian.PutUint16(payload[2:4], 0)  // version 0
	binary.BigEndian.PutUint32(payload[4:8], kafkaCorrelationID)
	binary.BigEndian.PutUint16(payload[8:10], uint16(len(clientID)))
	copy(payload[10:], clientID)
	request := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(request[:4], uint32(len(payload)))
	copy(request[4:], payload)
	if err := writeAll(connection, request); err != nil {
		return "", fmt.Errorf("send Kafka ApiVersions: %w", err)
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(connection, header); err != nil {
		return "", fmt.Errorf("read Kafka response length: %w", err)
	}
	length := binary.BigEndian.Uint32(header)
	if length < 6 || length > 16<<20 {
		return "", fmt.Errorf("invalid Kafka response length %d", length)
	}
	responseHeader := make([]byte, 6)
	if _, err := io.ReadFull(connection, responseHeader); err != nil {
		return "", fmt.Errorf("read Kafka ApiVersions response: %w", err)
	}
	correlationID := int32(binary.BigEndian.Uint32(responseHeader[:4]))
	if correlationID != kafkaCorrelationID {
		return "", fmt.Errorf("unexpected Kafka correlation id %d", correlationID)
	}
	errorCode := int16(binary.BigEndian.Uint16(responseHeader[4:6]))
	return fmt.Sprintf("ApiVersions v0 response (error code %d)", errorCode), nil
}
