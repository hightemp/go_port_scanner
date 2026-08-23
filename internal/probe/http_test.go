package probe

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestHTTPProbe(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		server     func(net.Conn) error
		wantDetail string
		wantError  string
	}{
		{
			name: "server header",
			server: probeHTTPServer(http.StatusNoContent, map[string]string{
				"Server": "Caddy",
			}),
			wantDetail: "HTTP/1.1 204 No Content; server Caddy",
		},
		{
			name:       "valid error status",
			server:     probeHTTPServer(http.StatusUnauthorized, nil),
			wantDetail: "HTTP/1.1 401 Unauthorized",
		},
		{
			name:      "invalid response",
			server:    invalidHTTPServer("SSH-2.0-OpenSSH\r\n"),
			wantError: "read http response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := runPipeProbe(t, httpProbe{}, tt.server)
			if tt.wantError != "" {
				if result.Err == nil || !strings.Contains(result.Err.Error(), tt.wantError) {
					t.Fatalf("Run() error = %v, want it to contain %q", result.Err, tt.wantError)
				}
				return
			}
			if result.Err != nil || result.Protocol != "http" || result.Detail != tt.wantDetail {
				t.Fatalf("Run() = %#v, want detail %q", result, tt.wantDetail)
			}
		})
	}
}

func probeHTTPServer(status int, headers map[string]string) func(net.Conn) error {
	return func(connection net.Conn) error {
		request, err := http.ReadRequest(bufio.NewReader(connection))
		if err != nil {
			return err
		}
		if request.Method != http.MethodHead || request.URL.Path != "/" || request.Host != "localhost:1234" {
			return fmt.Errorf("unexpected HTTP request %s %s host=%q", request.Method, request.URL.Path, request.Host)
		}
		if _, err := fmt.Fprintf(connection, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status)); err != nil {
			return err
		}
		for name, value := range headers {
			if _, err := fmt.Fprintf(connection, "%s: %s\r\n", name, value); err != nil {
				return err
			}
		}
		return writeAll(connection, []byte("Content-Length: 0\r\nConnection: close\r\n\r\n"))
	}
}

func invalidHTTPServer(response string) func(net.Conn) error {
	return func(connection net.Conn) error {
		if _, err := http.ReadRequest(bufio.NewReader(connection)); err != nil {
			return err
		}
		return writeAll(connection, []byte(response))
	}
}
