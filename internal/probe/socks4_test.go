package probe

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
)

func TestSOCKS4Probe(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		response   [8]byte
		wantDetail string
		wantError  string
	}{
		{name: "granted", response: socks4Response(0x5a), wantDetail: "SOCKS4-compatible; request granted"},
		{name: "rejected", response: socks4Response(0x5b), wantDetail: "SOCKS4-compatible; request rejected"},
		{name: "identd unavailable", response: socks4Response(0x5c), wantDetail: "SOCKS4-compatible; identd unavailable"},
		{name: "user ID rejected", response: socks4Response(0x5d), wantDetail: "SOCKS4-compatible; user ID rejected"},
		{name: "invalid version", response: [8]byte{4, 0x5b}, wantError: "unexpected SOCKS4 response version"},
		{name: "invalid status", response: [8]byte{0, 0x59}, wantError: "unexpected SOCKS4 response code"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := runPipeProbe(t, socks4Probe{}, socks4Server(tt.response))
			if tt.wantError != "" {
				if result.Err == nil || !strings.Contains(result.Err.Error(), tt.wantError) {
					t.Fatalf("Run() error = %v, want it to contain %q", result.Err, tt.wantError)
				}
				return
			}
			if result.Err != nil || result.Protocol != "socks4" || result.Detail != tt.wantDetail {
				t.Fatalf("Run() = %#v, want detail %q", result, tt.wantDetail)
			}
		})
	}
}

func socks4Response(status byte) [8]byte {
	return [8]byte{0, status, 0, 0, 0, 0, 0, 0}
}

func socks4Server(response [8]byte) func(net.Conn) error {
	return func(connection net.Conn) error {
		request := make([]byte, 9)
		if _, err := io.ReadFull(connection, request); err != nil {
			return err
		}
		wantRequest := []byte{4, 1, 0, 0, 0, 0, 0, 0, 0}
		if !bytes.Equal(request, wantRequest) {
			return fmt.Errorf("SOCKS4 request = %x, want %x", request, wantRequest)
		}
		return writeAll(connection, response[:])
	}
}
