package probe

import (
	"bufio"
	"context"
	"fmt"
	"net"
)

type ftpsExplicitProbe struct {
	tlsInsecureSkipVerify bool
}

func (ftpsExplicitProbe) Name() string { return "ftps_explicit" }

func (p ftpsExplicitProbe) Probe(ctx context.Context, connection net.Conn, target Target) (string, error) {
	reader := bufio.NewReader(connection)
	code, _, err := readFTPResponse(reader)
	if err != nil {
		return "", fmt.Errorf("read FTP greeting: %w", err)
	}
	if code != 220 {
		return "", fmt.Errorf("unexpected FTP greeting code %d", code)
	}
	if err := writeAll(connection, []byte("AUTH TLS\r\n")); err != nil {
		return "", fmt.Errorf("send AUTH TLS: %w", err)
	}
	code, message, err := readFTPResponse(reader)
	if err != nil {
		return "", fmt.Errorf("read AUTH TLS response: %w", err)
	}
	if code != 234 {
		return "", fmt.Errorf("AUTH TLS rejected with FTP code %d", code)
	}

	tlsConnection := tlsClient(connection, target.Host, p.tlsInsecureSkipVerify)
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		return "", fmt.Errorf("FTPS TLS handshake: %w", err)
	}
	return cleanDetail(message), nil
}
