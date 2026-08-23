package probe

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPSProbe(t *testing.T) {
	t.Parallel()

	certificateServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := certificateServer.TLS.Certificates[0]
	certificateServer.Close()

	server := func(connection net.Conn) error {
		tlsConnection := tls.Server(connection, &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
		})
		if err := tlsConnection.Handshake(); err != nil {
			return err
		}
		return probeHTTPServer(http.StatusNoContent, map[string]string{"Server": "secure-test"})(tlsConnection)
	}

	result := runPipeProbe(t, httpsProbe{tlsInsecureSkipVerify: true}, server)
	wantDetail := "TLS 1.2; HTTP/1.1 204 No Content; server secure-test"
	if result.Err != nil || result.Protocol != "https" || result.Detail != wantDetail {
		t.Fatalf("Run() = %#v, want detail %q", result, wantDetail)
	}
}
