package probe

import (
	"context"
	"fmt"
	"io"
	"net"
)

const (
	socks5Version             = 0x05
	socks5NoAuthentication    = 0x00
	socks5GSSAPI              = 0x01
	socks5UsernamePassword    = 0x02
	socks5NoAcceptableMethods = 0xff
)

type socks5Probe struct{}

func (socks5Probe) Name() string { return "socks5" }

func (socks5Probe) Probe(_ context.Context, connection net.Conn, _ Target) (string, error) {
	greeting := []byte{
		socks5Version,
		3,
		socks5NoAuthentication,
		socks5GSSAPI,
		socks5UsernamePassword,
	}
	if err := writeAll(connection, greeting); err != nil {
		return "", fmt.Errorf("send SOCKS5 greeting: %w", err)
	}

	var response [2]byte
	if _, err := io.ReadFull(connection, response[:]); err != nil {
		return "", fmt.Errorf("read SOCKS5 method selection: %w", err)
	}
	if response[0] != socks5Version {
		return "", fmt.Errorf("unexpected SOCKS version 0x%02x", response[0])
	}

	switch response[1] {
	case socks5NoAuthentication:
		return "SOCKS5; no authentication", nil
	case socks5GSSAPI:
		return "SOCKS5; GSSAPI authentication", nil
	case socks5UsernamePassword:
		return "SOCKS5; username/password authentication", nil
	case socks5NoAcceptableMethods:
		return "SOCKS5; offered authentication methods rejected", nil
	default:
		return "", fmt.Errorf("SOCKS5 server selected unoffered authentication method 0x%02x", response[1])
	}
}
