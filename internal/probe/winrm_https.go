package probe

import (
	"context"
	"fmt"
	"net"
)

type winrmHTTPSProbe struct {
	tlsInsecureSkipVerify bool
}

func (winrmHTTPSProbe) Name() string { return "winrm_https" }

func (p winrmHTTPSProbe) Probe(ctx context.Context, connection net.Conn, target Target) (string, error) {
	tlsConnection := tlsClient(connection, target.Host, p.tlsInsecureSkipVerify)
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		return "", fmt.Errorf("WinRM HTTPS TLS handshake: %w", err)
	}
	return probeWinRM(tlsConnection, target)
}
