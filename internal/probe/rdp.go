package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

type rdpProbe struct{}

func (rdpProbe) Name() string { return "rdp" }

func (rdpProbe) Probe(_ context.Context, connection net.Conn, _ Target) (string, error) {
	request := []byte{
		0x03, 0x00, 0x00, 0x13,
		0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x08, 0x00, 0x0b, 0x00, 0x00, 0x00,
	}
	if err := writeAll(connection, request); err != nil {
		return "", fmt.Errorf("send RDP X.224 Connection Request: %w", err)
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(connection, header); err != nil {
		return "", fmt.Errorf("read RDP TPKT header: %w", err)
	}
	length := int(binary.BigEndian.Uint16(header[2:4]))
	if header[0] != 3 || header[1] != 0 || length < 11 || length > 8192 {
		return "", fmt.Errorf("invalid RDP TPKT header %x", header)
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(connection, body); err != nil {
		return "", fmt.Errorf("read RDP X.224 Connection Confirm: %w", err)
	}
	if len(body) < 7 || body[1] != 0xd0 || int(body[0])+1 > len(body) {
		return "", fmt.Errorf("invalid RDP X.224 Connection Confirm")
	}
	if len(body) < 15 {
		return "X.224 Connection Confirm (standard RDP security)", nil
	}

	negotiation := body[7:15]
	if binary.LittleEndian.Uint16(negotiation[2:4]) != 8 {
		return "", fmt.Errorf("invalid RDP negotiation response length")
	}
	value := binary.LittleEndian.Uint32(negotiation[4:8])
	switch negotiation[0] {
	case 0x02:
		return fmt.Sprintf("X.224 Connection Confirm (selected protocol 0x%08x)", value), nil
	case 0x03:
		return fmt.Sprintf("X.224 Connection Confirm (negotiation failure 0x%08x)", value), nil
	default:
		return "", fmt.Errorf("unexpected RDP negotiation response type 0x%02x", negotiation[0])
	}
}
