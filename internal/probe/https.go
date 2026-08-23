package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
)

type httpsProbe struct {
	tlsInsecureSkipVerify bool
}

func (httpsProbe) Name() string { return "https" }

func (p httpsProbe) Probe(ctx context.Context, connection net.Conn, target Target) (string, error) {
	tlsConnection := tlsClient(connection, target.Host, p.tlsInsecureSkipVerify)
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		return "", fmt.Errorf("HTTPS TLS handshake: %w", err)
	}
	detail, err := probeHTTP(ctx, tlsConnection, target, "https")
	if err != nil {
		return "", err
	}
	return tls.VersionName(tlsConnection.ConnectionState().Version) + "; " + detail, nil
}
