package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const winRMIdentifyResponse = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">` +
	`<s:Body><wsmid:IdentifyResponse xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">` +
	`<wsmid:ProtocolVersion>http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd</wsmid:ProtocolVersion>` +
	`<wsmid:ProductVendor>Microsoft Corporation</wsmid:ProductVendor>` +
	`<wsmid:ProductVersion>OS: 10.0 Stack: 3.0</wsmid:ProductVersion>` +
	`</wsmid:IdentifyResponse></s:Body></s:Envelope>`

func TestProtocolProbes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		protocol   Prober
		server     func(net.Conn) error
		wantDetail string
	}{
		{
			name: "ssh", protocol: sshProbe{}, wantDetail: "SSH-2.0-OpenSSH_9.9",
			server: writeServer("notice\r\nSSH-2.0-OpenSSH_9.9\r\n"),
		},
		{
			name: "ftp", protocol: ftpProbe{}, wantDetail: "220 ready",
			server: writeServer("220-welcome\r\n220 ready\r\n"),
		},
		{
			name: "postgresql", protocol: postgresqlProbe{}, wantDetail: "SSL supported",
			server: func(connection net.Conn) error {
				request := make([]byte, 8)
				if _, err := io.ReadFull(connection, request); err != nil {
					return err
				}
				if binary.BigEndian.Uint32(request[4:]) != 80877103 {
					return fmt.Errorf("unexpected SSLRequest %x", request)
				}
				return writeAll(connection, []byte{'S'})
			},
		},
		{
			name: "mysql", protocol: mysqlProbe{}, wantDetail: "8.4.0",
			server: func(connection net.Conn) error {
				payload := append([]byte{0x0a}, []byte("8.4.0\x00")...)
				return writeAll(connection, append([]byte{byte(len(payload)), 0, 0, 0}, payload...))
			},
		},
		{
			name: "mongodb", protocol: mongodbProbe{}, wantDetail: "OP_MSG hello response",
			server: func(connection net.Conn) error {
				request := make([]byte, len(mongoHelloRequest()))
				if _, err := io.ReadFull(connection, request); err != nil {
					return err
				}
				response := make([]byte, 16)
				binary.LittleEndian.PutUint32(response[0:4], 16)
				binary.LittleEndian.PutUint32(response[8:12], mongoRequestID)
				binary.LittleEndian.PutUint32(response[12:16], mongoOPMsg)
				return writeAll(connection, response)
			},
		},
		{
			name: "mssql", protocol: mssqlProbe{}, wantDetail: "TDS PRELOGIN response",
			server: func(connection net.Conn) error {
				request := make([]byte, 26)
				if _, err := io.ReadFull(connection, request); err != nil {
					return err
				}
				return writeAll(connection, []byte{tdsReplyPacket, 1, 0, 8, 0, 0, 1, 0})
			},
		},
		{
			name: "cassandra", protocol: cassandraProbe{}, wantDetail: "native protocol v4 SUPPORTED response",
			server: func(connection net.Conn) error {
				request := make([]byte, 9)
				if _, err := io.ReadFull(connection, request); err != nil {
					return err
				}
				return writeAll(connection, []byte{0x84, 0, 0, 0, 0x06, 0, 0, 0, 0})
			},
		},
		{
			name: "elasticsearch", protocol: elasticsearchProbe{}, wantDetail: "version 8.17.0",
			server: httpServer(`{"name":"node","cluster_name":"cluster","version":{"number":"8.17.0"}}`, map[string]string{
				"X-Elastic-Product": "Elasticsearch",
			}),
		},
		{
			name: "rabbitmq", protocol: rabbitmqProbe{}, wantDetail: "AMQP 0-9-1 Connection.Start",
			server: func(connection net.Conn) error {
				request := make([]byte, 8)
				if _, err := io.ReadFull(connection, request); err != nil {
					return err
				}
				return writeAll(connection, []byte{1, 0, 0, 0, 0, 0, 4, 0, 10, 0, 10})
			},
		},
		{
			name: "kafka", protocol: kafkaProbe{}, wantDetail: "ApiVersions v0 response (error code 0)",
			server: func(connection net.Conn) error {
				length := make([]byte, 4)
				if _, err := io.ReadFull(connection, length); err != nil {
					return err
				}
				request := make([]byte, binary.BigEndian.Uint32(length))
				if _, err := io.ReadFull(connection, request); err != nil {
					return err
				}
				return writeAll(connection, []byte{0, 0, 0, 6, 0, 0, 0, 1, 0, 0})
			},
		},
		{
			name: "nats", protocol: natsProbe{}, wantDetail: "version 2.11.0, server demo",
			server: writeServer("INFO {\"version\":\"2.11.0\",\"server_name\":\"demo\"}\r\n"),
		},
		{
			name: "mqtt", protocol: mqttProbe{}, wantDetail: "MQTT 3.1.1 connection accepted",
			server: func(connection net.Conn) error {
				request := make([]byte, 29)
				if _, err := io.ReadFull(connection, request); err != nil {
					return err
				}
				return writeAll(connection, []byte{0x20, 0x02, 0x00, 0x00})
			},
		},
		{
			name: "redis", protocol: redisProbe{}, wantDetail: "PONG",
			server: func(connection net.Conn) error {
				request := make([]byte, len("*1\r\n$4\r\nPING\r\n"))
				if _, err := io.ReadFull(connection, request); err != nil {
					return err
				}
				return writeAll(connection, []byte("+PONG\r\n"))
			},
		},
		{
			name: "memcached", protocol: memcachedProbe{}, wantDetail: "1.6.32",
			server: func(connection net.Conn) error {
				request := make([]byte, len("version\r\n"))
				if _, err := io.ReadFull(connection, request); err != nil {
					return err
				}
				return writeAll(connection, []byte("VERSION 1.6.32\r\n"))
			},
		},
		{
			name: "etcd", protocol: etcdProbe{}, wantDetail: "server 3.6.0, cluster 3.6",
			server: httpServer(`{"etcdserver":"3.6.0","etcdcluster":"3.6"}`, nil),
		},
		{
			name: "rdp", protocol: rdpProbe{},
			wantDetail: "X.224 Connection Confirm (selected protocol 0x00000002)",
			server: readThenWriteServer(19, []byte{
				0x03, 0x00, 0x00, 0x13,
				0x0e, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
			}),
		},
		{
			name: "smb", protocol: smbProbe{},
			wantDetail: "SMB2 NEGOTIATE response (dialect 0x0311)",
			server: func(connection net.Conn) error {
				request := make([]byte, len(smbNegotiateRequest()))
				if _, err := io.ReadFull(connection, request); err != nil {
					return err
				}
				response := make([]byte, 4+129)
				response[3] = 129
				copy(response[4:8], []byte{'\xfe', 'S', 'M', 'B'})
				binary.LittleEndian.PutUint16(response[8:10], 64)
				binary.LittleEndian.PutUint32(response[20:24], 1)
				binary.LittleEndian.PutUint16(response[68:70], 65)
				binary.LittleEndian.PutUint16(response[72:74], 0x0311)
				return writeAll(connection, response)
			},
		},
		{
			name: "netbios", protocol: netbiosProbe{},
			wantDetail: "negative Session Response (code 0x82)",
			server:     readThenWriteServer(72, []byte{0x83, 0x00, 0x00, 0x01, 0x82}),
		},
		{
			name: "msrpc", protocol: msrpcProbe{},
			wantDetail: "DCE/RPC Endpoint Mapper bind_ack",
			server: readThenWriteServer(72, []byte{
				0x05, 0x00, 0x0c, 0x03, 0x10, 0x00, 0x00, 0x00,
				0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
			}),
		},
		{
			name: "kerberos", protocol: kerberosProbe{},
			wantDetail: "Kerberos KRB-ERROR",
			server: func(connection net.Conn) error {
				length := make([]byte, 4)
				if _, err := io.ReadFull(connection, length); err != nil {
					return err
				}
				request := make([]byte, binary.BigEndian.Uint32(length))
				if _, err := io.ReadFull(connection, request); err != nil {
					return err
				}
				return writeAll(connection, []byte{0, 0, 0, 5, 0x7e, 0x03, 0x30, 0x01, 0x00})
			},
		},
		{
			name: "ldap", protocol: ldapProbe{},
			wantDetail: "LDAPv3 BindResponse (result code 0)",
			server:     readThenWriteServer(14, ldapBindResponse(0)),
		},
		{
			name: "winrm", protocol: winrmProbe{},
			wantDetail: "Microsoft Corporation OS: 10.0 Stack: 3.0",
			server:     httpServer(winRMIdentifyResponse, nil),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := runPipeProbe(t, tt.protocol, tt.server)
			if result.Err != nil {
				t.Fatalf("Run() error = %v", result.Err)
			}
			if result.Protocol != tt.name || result.Detail != tt.wantDetail {
				t.Errorf("Run() = %#v, want protocol %q and detail %q", result, tt.name, tt.wantDetail)
			}
		})
	}
}

func TestTLSProbes(t *testing.T) {
	t.Parallel()

	certificateServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := certificateServer.TLS.Certificates[0]
	certificateServer.Close()

	tests := []struct {
		name       string
		protocol   Prober
		server     func(net.Conn) error
		wantDetail string
	}{
		{
			name:       "explicit",
			protocol:   ftpsExplicitProbe{tlsInsecureSkipVerify: true},
			wantDetail: "234 continue",
			server: func(connection net.Conn) error {
				if err := writeAll(connection, []byte("220 ready\r\n")); err != nil {
					return err
				}
				line, err := readLine(bufio.NewReader(connection), maxTextLine)
				if err != nil {
					return err
				}
				if line != "AUTH TLS" {
					return fmt.Errorf("command = %q", line)
				}
				if err := writeAll(connection, []byte("234 continue\r\n")); err != nil {
					return err
				}
				return tls.Server(connection, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}).Handshake()
			},
		},
		{
			name:       "implicit",
			protocol:   ftpsImplicitProbe{tlsInsecureSkipVerify: true},
			wantDetail: "220 secure ready",
			server: func(connection net.Conn) error {
				tlsConnection := tls.Server(connection, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
				if err := tlsConnection.Handshake(); err != nil {
					return err
				}
				return writeAll(tlsConnection, []byte("220 secure ready\r\n"))
			},
		},
		{
			name:       "ldaps",
			protocol:   ldapsProbe{tlsInsecureSkipVerify: true},
			wantDetail: "LDAPv3 BindResponse (result code 0)",
			server: func(connection net.Conn) error {
				tlsConnection := tls.Server(connection, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
				if err := tlsConnection.Handshake(); err != nil {
					return err
				}
				request := make([]byte, 14)
				if _, err := io.ReadFull(tlsConnection, request); err != nil {
					return err
				}
				return writeAll(tlsConnection, ldapBindResponse(0))
			},
		},
		{
			name:       "winrm https",
			protocol:   winrmHTTPSProbe{tlsInsecureSkipVerify: true},
			wantDetail: "Microsoft Corporation OS: 10.0 Stack: 3.0",
			server: func(connection net.Conn) error {
				tlsConnection := tls.Server(connection, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
				if err := tlsConnection.Handshake(); err != nil {
					return err
				}
				return httpServer(winRMIdentifyResponse, nil)(tlsConnection)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := runPipeProbe(t, tt.protocol, tt.server)
			if result.Err != nil || result.Detail != tt.wantDetail {
				t.Fatalf("Run() = %#v, want detail %q", result, tt.wantDetail)
			}
		})
	}
}

func TestRegistry(t *testing.T) {
	t.Parallel()

	names := []string{
		"ssh", "ftp", "ftps_explicit", "ftps_implicit", "http", "https", "socks", "postgresql", "mysql", "mongodb", "mssql",
		"cassandra", "elasticsearch", "rabbitmq", "kafka", "nats", "mqtt", "redis", "memcached", "etcd",
		"rdp", "smb", "netbios", "msrpc", "kerberos", "ldap", "ldaps", "winrm", "winrm_https",
	}
	definitions := make([]Definition, 0, len(names)+1)
	for _, name := range names {
		definitions = append(definitions, Definition{Name: name, Ports: []int{22}})
	}
	definitions = append(definitions, Definition{Name: "ssh", Ports: []int{2222}})
	registry, err := NewRegistry(Config{
		Timeout:     time.Second,
		Definitions: definitions,
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	if got := registry.Count(); got != 30 {
		t.Errorf("Count() = %d, want 30", got)
	}
	protocols := registry.ForPort(22)
	if len(protocols) != len(names) || protocols[0].Name() != "ssh" || protocols[1].Name() != "ftp" {
		t.Errorf("ForPort(22) = %v, want all protocols in order", protocols)
	}
	if got := (*Registry)(nil).ForPort(22); got != nil {
		t.Errorf("nil Registry.ForPort() = %v, want nil", got)
	}
	if got := (*Registry)(nil).Count(); got != 0 {
		t.Errorf("nil Registry.Count() = %d, want 0", got)
	}

	invalid := []Config{
		{},
		{Timeout: time.Second, Definitions: []Definition{{Name: "unknown", Ports: []int{1}}}},
		{Timeout: time.Second, Definitions: []Definition{{Name: "ssh"}}},
		{Timeout: time.Second, Definitions: []Definition{{Name: "ssh", Ports: []int{0}}}},
	}
	for _, configuration := range invalid {
		if _, err := NewRegistry(configuration); err == nil {
			t.Errorf("NewRegistry(%#v) error = nil", configuration)
		}
	}
}

func TestProtocolRejections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		protocol Prober
		server   func(net.Conn) error
	}{
		{
			name: "ftps explicit rejects auth", protocol: ftpsExplicitProbe{tlsInsecureSkipVerify: true},
			server: func(connection net.Conn) error {
				if err := writeAll(connection, []byte("220 ready\r\n")); err != nil {
					return err
				}
				if _, err := readLine(bufio.NewReader(connection), maxTextLine); err != nil {
					return err
				}
				return writeAll(connection, []byte("534 rejected\r\n"))
			},
		},
		{
			name: "postgresql invalid", protocol: postgresqlProbe{},
			server: readThenWriteServer(8, []byte{'X'}),
		},
		{
			name: "mysql protocol", protocol: mysqlProbe{},
			server: writeServerBytes([]byte{1, 0, 0, 0, 9}),
		},
		{
			name: "mongodb response id", protocol: mongodbProbe{},
			server: func(connection net.Conn) error {
				request := make([]byte, len(mongoHelloRequest()))
				_, _ = io.ReadFull(connection, request)
				response := make([]byte, 16)
				binary.LittleEndian.PutUint32(response[0:4], 16)
				binary.LittleEndian.PutUint32(response[8:12], 99)
				binary.LittleEndian.PutUint32(response[12:16], mongoOPMsg)
				return writeAll(connection, response)
			},
		},
		{
			name: "mssql packet", protocol: mssqlProbe{},
			server: readThenWriteServer(26, []byte{0x05, 1, 0, 8, 0, 0, 1, 0}),
		},
		{
			name: "cassandra version", protocol: cassandraProbe{},
			server: readThenWriteServer(9, []byte{0x83, 0, 0, 0, 0x06, 0, 0, 0, 0}),
		},
		{
			name: "elasticsearch identity", protocol: elasticsearchProbe{},
			server: httpServer(`{}`, nil),
		},
		{
			name: "rabbitmq method", protocol: rabbitmqProbe{},
			server: readThenWriteServer(8, []byte{1, 0, 0, 0, 0, 0, 4, 0, 20, 0, 10}),
		},
		{
			name: "kafka correlation", protocol: kafkaProbe{},
			server: func(connection net.Conn) error {
				length := make([]byte, 4)
				if _, err := io.ReadFull(connection, length); err != nil {
					return err
				}
				request := make([]byte, binary.BigEndian.Uint32(length))
				if _, err := io.ReadFull(connection, request); err != nil {
					return err
				}
				return writeAll(connection, []byte{0, 0, 0, 6, 0, 0, 0, 2, 0, 0})
			},
		},
		{
			name: "mqtt connack", protocol: mqttProbe{},
			server: readThenWriteServer(29, []byte{0x20, 0x03, 0, 0}),
		},
		{
			name: "etcd identity", protocol: etcdProbe{},
			server: httpServer(`{}`, nil),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := runPipeProbe(t, tt.protocol, tt.server)
			if result.Err == nil {
				t.Fatalf("Run() error = nil, result = %#v", result)
			}
		})
	}
}

func TestAlternativeProtocolResponses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		protocol   Prober
		server     func(net.Conn) error
		wantDetail string
	}{
		{
			name: "mysql error", protocol: mysqlProbe{},
			server:     writeServerBytes([]byte{3, 0, 0, 0, 0xff, 0x15, 0x04}),
			wantDetail: "server error 1045",
		},
		{
			name: "cassandra error", protocol: cassandraProbe{},
			server:     readThenWriteServer(9, []byte{0x84, 0, 0, 0, 0x00, 0, 0, 0, 0}),
			wantDetail: "native protocol v4 error response",
		},
		{
			name: "mqtt refused", protocol: mqttProbe{},
			server:     readThenWriteServer(29, []byte{0x20, 0x02, 0, 5}),
			wantDetail: "MQTT 3.1.1 connection refused (code 5)",
		},
		{
			name: "redis noauth", protocol: redisProbe{},
			server:     readThenWriteServer(len("*1\r\n$4\r\nPING\r\n"), []byte("-NOAUTH authentication required\r\n")),
			wantDetail: "NOAUTH authentication required",
		},
		{
			name: "rdp negotiation failure", protocol: rdpProbe{},
			server: readThenWriteServer(19, []byte{
				0x03, 0x00, 0x00, 0x13,
				0x0e, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x03, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
			}),
			wantDetail: "X.224 Connection Confirm (negotiation failure 0x00000002)",
		},
		{
			name: "smb status", protocol: smbProbe{},
			server: func(connection net.Conn) error {
				request := make([]byte, len(smbNegotiateRequest()))
				_, _ = io.ReadFull(connection, request)
				response := make([]byte, 4+64)
				response[3] = 64
				copy(response[4:8], []byte{'\xfe', 'S', 'M', 'B'})
				binary.LittleEndian.PutUint16(response[8:10], 64)
				binary.LittleEndian.PutUint32(response[12:16], 0xc0000022)
				binary.LittleEndian.PutUint32(response[20:24], 1)
				return writeAll(connection, response)
			},
			wantDetail: "SMB2 NEGOTIATE response (status 0xc0000022)",
		},
		{
			name: "netbios positive", protocol: netbiosProbe{},
			server:     readThenWriteServer(72, []byte{0x82, 0, 0, 0}),
			wantDetail: "positive Session Response",
		},
		{
			name: "msrpc bind nak", protocol: msrpcProbe{},
			server: readThenWriteServer(72, []byte{
				0x05, 0x00, 0x0d, 0x03, 0x10, 0x00, 0x00, 0x00,
				0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
			}),
			wantDetail: "DCE/RPC Endpoint Mapper bind_nak",
		},
		{
			name: "kerberos as rep", protocol: kerberosProbe{},
			server:     kerberosServerResponse([]byte{0x6b, 0x03, 0x30, 0x01, 0x00}),
			wantDetail: "Kerberos AS-REP",
		},
		{
			name: "ldap denied", protocol: ldapProbe{},
			server:     readThenWriteServer(14, ldapBindResponse(49)),
			wantDetail: "LDAPv3 BindResponse (result code 49)",
		},
		{
			name: "winrm auth", protocol: winrmProbe{},
			server: httpStatusServer(http.StatusUnauthorized, "", map[string]string{
				"WWW-Authenticate": "Negotiate, NTLM",
			}),
			wantDetail: "HTTP 401 authentication challenge (Negotiate, NTLM)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := runPipeProbe(t, tt.protocol, tt.server)
			if result.Err != nil || result.Detail != tt.wantDetail {
				t.Fatalf("Run() = %#v, want detail %q", result, tt.wantDetail)
			}
		})
	}
}

func TestRegistryRunDeadlineError(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	registry := &Registry{timeout: time.Second}
	result := registry.Run(context.Background(), sshProbe{}, deadlineErrorConnection{Conn: client}, Target{})
	if result.Err == nil || !strings.Contains(result.Err.Error(), "set probe deadline") {
		t.Fatalf("Run() = %#v, want deadline error", result)
	}
}

func TestProbeFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		protocol Prober
		response string
	}{
		{name: "ssh", protocol: sshProbe{}, response: "HTTP/1.1 200 OK\r\n"},
		{name: "ftp", protocol: ftpProbe{}, response: "500 no\r\n"},
		{name: "nats", protocol: natsProbe{}, response: "HELLO\r\n"},
		{name: "redis", protocol: redisProbe{}, response: "+OK\r\n"},
		{name: "memcached", protocol: memcachedProbe{}, response: "ERROR\r\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := runPipeProbe(t, tt.protocol, func(connection net.Conn) error {
				if tt.name == "redis" {
					request := make([]byte, len("*1\r\n$4\r\nPING\r\n"))
					_, _ = io.ReadFull(connection, request)
				} else if tt.name == "memcached" {
					request := make([]byte, len("version\r\n"))
					_, _ = io.ReadFull(connection, request)
				}
				return writeAll(connection, []byte(tt.response))
			})
			if result.Err == nil {
				t.Fatalf("Run() error = nil, result = %#v", result)
			}
		})
	}
}

func TestHelpers(t *testing.T) {
	t.Parallel()

	if got := cleanDetail(" hello\nworld "); got != "hello world" {
		t.Errorf("cleanDetail() = %q", got)
	}
	if got := cleanDetail(strings.Repeat("x", 201)); len(got) != 203 || !strings.HasSuffix(got, "...") {
		t.Errorf("cleanDetail(long) length = %d, value = %q", len(got), got)
	}
	if _, err := readLine(bufio.NewReader(strings.NewReader("too long\n")), 3); err == nil {
		t.Fatal("readLine() error = nil for oversized line")
	}
}

func TestWindowsProtocolHelpers(t *testing.T) {
	t.Parallel()

	if got := kerberosRealm("dc.example.com"); got != "EXAMPLE.COM" {
		t.Errorf("kerberosRealm() = %q, want EXAMPLE.COM", got)
	}
	if got := kerberosRealm("192.0.2.1"); got != "INVALID" {
		t.Errorf("kerberosRealm(IP) = %q, want INVALID", got)
	}
	if encoded := derInteger(300); len(encoded) < 4 {
		t.Errorf("derInteger(300) = %x", encoded)
	}
	if encoded := derWrap(0x04, make([]byte, 300)); len(encoded) != 304 {
		t.Errorf("derWrap(300 bytes) length = %d, want 304", len(encoded))
	}

	tag, value, err := readBERElement(strings.NewReader("\x04\x81\x03abc"), 10)
	if err != nil || tag != 0x04 || string(value) != "abc" {
		t.Errorf("readBERElement() = 0x%02x, %q, %v", tag, value, err)
	}
	for _, input := range []string{"\x04\x80", "\x04\x02ab"} {
		if _, _, err := readBERElement(strings.NewReader(input), 1); err == nil {
			t.Errorf("readBERElement(%q) error = nil", input)
		}
	}
}

func runPipeProbe(t *testing.T, protocol Prober, server func(net.Conn) error) Result {
	t.Helper()
	clientConnection, serverConnection := net.Pipe()
	serverErrors := make(chan error, 1)
	go func() {
		defer serverConnection.Close()
		serverErrors <- server(serverConnection)
	}()

	registry := &Registry{timeout: time.Second}
	result := registry.Run(context.Background(), protocol, clientConnection, Target{Host: "localhost", Port: 1234})
	if err := clientConnection.Close(); err != nil {
		t.Errorf("clientConnection.Close() error = %v", err)
	}
	if err := <-serverErrors; err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("mock server error = %v", err)
	}
	return result
}

func writeServer(response string) func(net.Conn) error {
	return func(connection net.Conn) error {
		return writeAll(connection, []byte(response))
	}
}

func writeServerBytes(response []byte) func(net.Conn) error {
	return func(connection net.Conn) error {
		return writeAll(connection, response)
	}
}

func readThenWriteServer(readBytes int, response []byte) func(net.Conn) error {
	return func(connection net.Conn) error {
		request := make([]byte, readBytes)
		if _, err := io.ReadFull(connection, request); err != nil {
			return err
		}
		return writeAll(connection, response)
	}
}

func kerberosServerResponse(response []byte) func(net.Conn) error {
	return func(connection net.Conn) error {
		length := make([]byte, 4)
		if _, err := io.ReadFull(connection, length); err != nil {
			return err
		}
		request := make([]byte, binary.BigEndian.Uint32(length))
		if _, err := io.ReadFull(connection, request); err != nil {
			return err
		}
		framed := make([]byte, 4+len(response))
		binary.BigEndian.PutUint32(framed[:4], uint32(len(response)))
		copy(framed[4:], response)
		return writeAll(connection, framed)
	}
}

func ldapBindResponse(resultCode byte) []byte {
	return []byte{
		0x30, 0x0c,
		0x02, 0x01, 0x01,
		0x61, 0x07,
		0x0a, 0x01, resultCode,
		0x04, 0x00,
		0x04, 0x00,
	}
}

func httpServer(body string, headers map[string]string) func(net.Conn) error {
	return httpStatusServer(http.StatusOK, body, headers)
}

func httpStatusServer(status int, body string, headers map[string]string) func(net.Conn) error {
	return func(connection net.Conn) error {
		request, err := http.ReadRequest(bufio.NewReader(connection))
		if err != nil {
			return err
		}
		if request.URL.Path != "/" && request.URL.Path != "/version" && request.URL.Path != "/wsman" {
			return fmt.Errorf("unexpected path %q", request.URL.Path)
		}
		if _, err := fmt.Fprintf(connection, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status)); err != nil {
			return err
		}
		for name, value := range headers {
			if _, err := fmt.Fprintf(connection, "%s: %s\r\n", name, value); err != nil {
				return err
			}
		}
		_, err = fmt.Fprintf(connection, "Content-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
		return err
	}
}

type deadlineErrorConnection struct {
	net.Conn
}

func (deadlineErrorConnection) SetDeadline(time.Time) error {
	return errors.New("deadline unavailable")
}
