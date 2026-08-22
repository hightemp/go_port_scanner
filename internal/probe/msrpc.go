package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

type msrpcProbe struct{}

func (msrpcProbe) Name() string { return "msrpc" }

func (msrpcProbe) Probe(_ context.Context, connection net.Conn, _ Target) (string, error) {
	request := []byte{
		0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00,
		0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x01, 0x00,
		0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11,
		0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa,
		0x03, 0x00, 0x00, 0x00,
		0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
		0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
		0x02, 0x00, 0x00, 0x00,
	}
	if err := writeAll(connection, request); err != nil {
		return "", fmt.Errorf("send MSRPC Endpoint Mapper bind: %w", err)
	}

	header := make([]byte, 16)
	if _, err := io.ReadFull(connection, header); err != nil {
		return "", fmt.Errorf("read MSRPC bind response: %w", err)
	}
	fragmentLength := int(binary.LittleEndian.Uint16(header[8:10]))
	if header[0] != 5 || header[1] != 0 || header[4] != 0x10 || fragmentLength < 16 || fragmentLength > 65535 {
		return "", fmt.Errorf("invalid MSRPC common header")
	}
	if binary.LittleEndian.Uint32(header[12:16]) != 1 {
		return "", fmt.Errorf("unexpected MSRPC call id")
	}
	switch header[2] {
	case 0x0c:
		return "DCE/RPC Endpoint Mapper bind_ack", nil
	case 0x0d:
		return "DCE/RPC Endpoint Mapper bind_nak", nil
	default:
		return "", fmt.Errorf("unexpected MSRPC bind response type 0x%02x", header[2])
	}
}
