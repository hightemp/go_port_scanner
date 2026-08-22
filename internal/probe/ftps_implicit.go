package probe

import (
	"bufio"
	"context"
	"fmt"
	"net"
)

type ftpsImplicitProbe struct {
	tlsInsecureSkipVerify bool
}

func (ftpsImplicitProbe) Name() string { return "ftps_implicit" }

func (p ftpsImplicitProbe) Probe(ctx context.Context, connection net.Conn, target Target) (string, error) {
	tlsConnection := tlsClient(connection, target.Host, p.tlsInsecureSkipVerify)
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		return "", fmt.Errorf("FTPS TLS handshake: %w", err)
	}
	code, message, err := readFTPResponse(bufio.NewReader(tlsConnection))
	if err != nil {
		return "", fmt.Errorf("read FTPS greeting: %w", err)
	}
	if code != 220 {
		return "", fmt.Errorf("unexpected FTPS greeting code %d", code)
	}
	return cleanDetail(message), nil
}
