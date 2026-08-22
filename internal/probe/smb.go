package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const maxSMBMessage = 1 << 20

type smbProbe struct{}

func (smbProbe) Name() string { return "smb" }

func (smbProbe) Probe(_ context.Context, connection net.Conn, _ Target) (string, error) {
	request := smbNegotiateRequest()
	if err := writeAll(connection, request); err != nil {
		return "", fmt.Errorf("send SMB2 NEGOTIATE: %w", err)
	}

	netbiosHeader := make([]byte, 4)
	if _, err := io.ReadFull(connection, netbiosHeader); err != nil {
		return "", fmt.Errorf("read SMB message header: %w", err)
	}
	length := int(netbiosHeader[1])<<16 | int(netbiosHeader[2])<<8 | int(netbiosHeader[3])
	if netbiosHeader[0] != 0 || length < 64 || length > maxSMBMessage {
		return "", fmt.Errorf("invalid SMB message length %d", length)
	}
	header := make([]byte, 64)
	if _, err := io.ReadFull(connection, header); err != nil {
		return "", fmt.Errorf("read SMB2 header: %w", err)
	}
	if string(header[:4]) != "\xfeSMB" || binary.LittleEndian.Uint16(header[4:6]) != 64 ||
		binary.LittleEndian.Uint16(header[12:14]) != 0 || binary.LittleEndian.Uint32(header[16:20])&1 == 0 {
		return "", fmt.Errorf("invalid SMB2 NEGOTIATE response")
	}
	status := binary.LittleEndian.Uint32(header[8:12])
	if status != 0 {
		return fmt.Sprintf("SMB2 NEGOTIATE response (status 0x%08x)", status), nil
	}
	if length < 129 {
		return "", fmt.Errorf("short SMB2 NEGOTIATE response")
	}
	response := make([]byte, length-64)
	if _, err := io.ReadFull(connection, response); err != nil {
		return "", fmt.Errorf("read SMB2 NEGOTIATE response: %w", err)
	}
	if binary.LittleEndian.Uint16(response[:2]) != 65 {
		return "", fmt.Errorf("invalid SMB2 NEGOTIATE structure size")
	}
	dialect := binary.LittleEndian.Uint16(response[4:6])
	return fmt.Sprintf("SMB2 NEGOTIATE response (dialect 0x%04x)", dialect), nil
}

func smbNegotiateRequest() []byte {
	payload := make([]byte, 64+36+2)
	copy(payload[:4], []byte{'\xfe', 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(payload[4:6], 64)
	binary.LittleEndian.PutUint16(payload[12:14], 0)
	binary.LittleEndian.PutUint16(payload[14:16], 1)

	request := payload[64:]
	binary.LittleEndian.PutUint16(request[0:2], 36)
	binary.LittleEndian.PutUint16(request[2:4], 1)
	binary.LittleEndian.PutUint16(request[4:6], 1)
	copy(request[12:28], []byte{
		0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	})
	binary.LittleEndian.PutUint16(request[36:38], 0x0202)

	framed := make([]byte, 4+len(payload))
	framed[1] = byte(len(payload) >> 16)
	framed[2] = byte(len(payload) >> 8)
	framed[3] = byte(len(payload))
	copy(framed[4:], payload)
	return framed
}
