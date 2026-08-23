package probe

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
)

func TestSOCKSProbe(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		response   [2]byte
		wantDetail string
		wantError  string
	}{
		{name: "no authentication", response: [2]byte{5, 0}, wantDetail: "SOCKS5; no authentication"},
		{name: "GSSAPI", response: [2]byte{5, 1}, wantDetail: "SOCKS5; GSSAPI authentication"},
		{name: "username password", response: [2]byte{5, 2}, wantDetail: "SOCKS5; username/password authentication"},
		{name: "methods rejected", response: [2]byte{5, 0xff}, wantDetail: "SOCKS5; offered authentication methods rejected"},
		{name: "invalid version", response: [2]byte{4, 0}, wantError: "unexpected SOCKS version"},
		{name: "unoffered method", response: [2]byte{5, 0x80}, wantError: "unoffered authentication method"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := runPipeProbe(t, socksProbe{}, socksServer(tt.response))
			if tt.wantError != "" {
				if result.Err == nil || !strings.Contains(result.Err.Error(), tt.wantError) {
					t.Fatalf("Run() error = %v, want it to contain %q", result.Err, tt.wantError)
				}
				return
			}
			if result.Err != nil || result.Protocol != "socks" || result.Detail != tt.wantDetail {
				t.Fatalf("Run() = %#v, want detail %q", result, tt.wantDetail)
			}
		})
	}
}

func socksServer(response [2]byte) func(net.Conn) error {
	return func(connection net.Conn) error {
		greeting := make([]byte, 5)
		if _, err := io.ReadFull(connection, greeting); err != nil {
			return err
		}
		wantGreeting := []byte{5, 3, 0, 1, 2}
		if !bytes.Equal(greeting, wantGreeting) {
			return fmt.Errorf("SOCKS5 greeting = %x, want %x", greeting, wantGreeting)
		}
		return writeAll(connection, response[:])
	}
}
