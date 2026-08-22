package probe

import (
	"context"
	"fmt"
	"io"
	"net"
)

type mqttProbe struct{}

func (mqttProbe) Name() string { return "mqtt" }

func (mqttProbe) Probe(_ context.Context, connection net.Conn, _ Target) (string, error) {
	clientID := []byte("go-port-scanner")
	remainingLength := 10 + 2 + len(clientID)
	request := []byte{
		0x10, byte(remainingLength),
		0x00, 0x04, 'M', 'Q', 'T', 'T',
		0x04, 0x02, 0x00, 0x00,
		byte(len(clientID) >> 8), byte(len(clientID)),
	}
	request = append(request, clientID...)
	if err := writeAll(connection, request); err != nil {
		return "", fmt.Errorf("send MQTT CONNECT: %w", err)
	}

	response := make([]byte, 4)
	if _, err := io.ReadFull(connection, response); err != nil {
		return "", fmt.Errorf("read MQTT CONNACK: %w", err)
	}
	if response[0] != 0x20 || response[1] != 0x02 || response[2]&0xfe != 0 || response[3] > 5 {
		return "", fmt.Errorf("invalid MQTT CONNACK %x", response)
	}
	if response[3] == 0 {
		return "MQTT 3.1.1 connection accepted", nil
	}
	return fmt.Sprintf("MQTT 3.1.1 connection refused (code %d)", response[3]), nil
}
