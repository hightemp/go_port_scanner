package probe

import (
	"crypto/tls"
	"net"
)

func tlsClient(connection net.Conn, host string, insecureSkipVerify bool) *tls.Conn {
	return tls.Client(connection, &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         host,
		InsecureSkipVerify: insecureSkipVerify, //nolint:gosec // Explicit user-controlled probe setting.
	})
}
