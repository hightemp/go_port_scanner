package probe

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
)

type netbiosProbe struct{}

func (netbiosProbe) Name() string { return "netbios" }

func (netbiosProbe) Probe(_ context.Context, connection net.Conn, _ Target) (string, error) {
	calledName := encodeNetBIOSName("*SMBSERVER", 0x20)
	callingName := encodeNetBIOSName("GOPORTSCANNER", 0x00)
	payloadLength := len(calledName) + len(callingName)
	request := []byte{0x81, 0x00, byte(payloadLength >> 8), byte(payloadLength)}
	request = append(request, calledName...)
	request = append(request, callingName...)
	if err := writeAll(connection, request); err != nil {
		return "", fmt.Errorf("send NetBIOS Session Request: %w", err)
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(connection, header); err != nil {
		return "", fmt.Errorf("read NetBIOS Session response: %w", err)
	}
	length := int(header[1]&0x01)<<16 | int(header[2])<<8 | int(header[3])
	if header[1]&0xfe != 0 || length > 65536 {
		return "", fmt.Errorf("invalid NetBIOS Session response header %x", header)
	}
	switch header[0] {
	case 0x82:
		if length != 0 {
			return "", fmt.Errorf("invalid positive NetBIOS Session response length %d", length)
		}
		return "positive Session Response", nil
	case 0x83:
		if length != 1 {
			return "", fmt.Errorf("invalid negative NetBIOS Session response length %d", length)
		}
		code := []byte{0}
		if _, err := io.ReadFull(connection, code); err != nil {
			return "", fmt.Errorf("read NetBIOS Session error code: %w", err)
		}
		return fmt.Sprintf("negative Session Response (code 0x%02x)", code[0]), nil
	case 0x84:
		return "retarget Session Response", nil
	default:
		return "", fmt.Errorf("unexpected NetBIOS Session response type 0x%02x", header[0])
	}
}

func encodeNetBIOSName(name string, suffix byte) []byte {
	raw := make([]byte, 16)
	for index := range 15 {
		raw[index] = ' '
	}
	copy(raw[:15], strings.ToUpper(name))
	raw[15] = suffix

	encoded := make([]byte, 34)
	encoded[0] = 32
	for index, value := range raw {
		encoded[1+index*2] = 'A' + value>>4
		encoded[2+index*2] = 'A' + value&0x0f
	}
	return encoded
}
