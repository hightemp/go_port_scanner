package probe

import (
	"context"
	"fmt"
	"net"
)

type ldapsProbe struct {
	tlsInsecureSkipVerify bool
}

func (ldapsProbe) Name() string { return "ldaps" }

func (p ldapsProbe) Probe(ctx context.Context, connection net.Conn, target Target) (string, error) {
	tlsConnection := tlsClient(connection, target.Host, p.tlsInsecureSkipVerify)
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		return "", fmt.Errorf("LDAPS TLS handshake: %w", err)
	}
	return probeLDAP(tlsConnection)
}
