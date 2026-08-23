package probe

import (
	"context"
	"fmt"
	"io"
	"net"
)

const (
	socks4Version           = 0x04
	socks4CommandConnect    = 0x01
	socks4ResponseVersion   = 0x00
	socks4RequestGranted    = 0x5a
	socks4RequestRejected   = 0x5b
	socks4IdentdUnavailable = 0x5c
	socks4UserIDRejected    = 0x5d
)

type socks4Probe struct{}

func (socks4Probe) Name() string { return "socks4" }

func (socks4Probe) Probe(_ context.Context, connection net.Conn, _ Target) (string, error) {
	// SOCKS4 has no negotiation-only request. Port zero and 0.0.0.0 prevent
	// this identification request from targeting a real external endpoint.
	request := []byte{
		socks4Version,
		socks4CommandConnect,
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00,
	}
	if err := writeAll(connection, request); err != nil {
		return "", fmt.Errorf("send SOCKS4 identification request: %w", err)
	}

	var response [8]byte
	if _, err := io.ReadFull(connection, response[:]); err != nil {
		return "", fmt.Errorf("read SOCKS4 response: %w", err)
	}
	if response[0] != socks4ResponseVersion {
		return "", fmt.Errorf("unexpected SOCKS4 response version 0x%02x", response[0])
	}

	switch response[1] {
	case socks4RequestGranted:
		return "SOCKS4-compatible; request granted", nil
	case socks4RequestRejected:
		return "SOCKS4-compatible; request rejected", nil
	case socks4IdentdUnavailable:
		return "SOCKS4-compatible; identd unavailable", nil
	case socks4UserIDRejected:
		return "SOCKS4-compatible; user ID rejected", nil
	default:
		return "", fmt.Errorf("unexpected SOCKS4 response code 0x%02x", response[1])
	}
}
