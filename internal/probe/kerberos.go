package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const maxKerberosMessage = 1 << 20

type kerberosProbe struct{}

func (kerberosProbe) Name() string { return "kerberos" }

func (kerberosProbe) Probe(_ context.Context, connection net.Conn, target Target) (string, error) {
	realm := kerberosRealm(target.Host)
	requestPayload := kerberosASRequest(realm, time.Now().UTC().Add(5*time.Minute))
	request := make([]byte, 4+len(requestPayload))
	binary.BigEndian.PutUint32(request[:4], uint32(len(requestPayload)))
	copy(request[4:], requestPayload)
	if err := writeAll(connection, request); err != nil {
		return "", fmt.Errorf("send Kerberos AS-REQ: %w", err)
	}

	lengthBytes := make([]byte, 4)
	if _, err := io.ReadFull(connection, lengthBytes); err != nil {
		return "", fmt.Errorf("read Kerberos response length: %w", err)
	}
	length := binary.BigEndian.Uint32(lengthBytes)
	if length < 2 || length > maxKerberosMessage {
		return "", fmt.Errorf("invalid Kerberos response length %d", length)
	}
	response := make([]byte, length)
	if _, err := io.ReadFull(connection, response); err != nil {
		return "", fmt.Errorf("read Kerberos response: %w", err)
	}
	switch response[0] {
	case 0x6b:
		return "Kerberos AS-REP", nil
	case 0x7e:
		return "Kerberos KRB-ERROR", nil
	default:
		return "", fmt.Errorf("unexpected Kerberos application tag 0x%02x", response[0])
	}
}

func kerberosRealm(host string) string {
	if net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return "INVALID"
	}
	parts := strings.SplitN(host, ".", 2)
	return strings.ToUpper(parts[1])
}

func kerberosASRequest(realm string, till time.Time) []byte {
	cname := kerberosPrincipal(1, "go-port-scanner")
	sname := kerberosPrincipal(2, "krbtgt", realm)
	etypes := derWrap(0x30, append(derInteger(18), append(derInteger(17), derInteger(23)...)...))
	body := derWrap(0x30, joinBytes(
		derContext(0, derWrap(0x03, []byte{0, 0, 0, 0, 0})),
		derContext(1, cname),
		derContext(2, derGeneralString(realm)),
		derContext(3, sname),
		derContext(5, derWrap(0x18, []byte(till.Format("20060102150405Z")))),
		derContext(7, derInteger(1)),
		derContext(8, etypes),
	))
	kdcRequest := derWrap(0x30, joinBytes(
		derContext(1, derInteger(5)),
		derContext(2, derInteger(10)),
		derContext(4, body),
	))
	return derWrap(0x6a, kdcRequest)
}

func kerberosPrincipal(nameType int, components ...string) []byte {
	names := make([][]byte, 0, len(components))
	for _, component := range components {
		names = append(names, derGeneralString(component))
	}
	return derWrap(0x30, joinBytes(
		derContext(0, derInteger(nameType)),
		derContext(1, derWrap(0x30, joinBytes(names...))),
	))
}

func derContext(number byte, value []byte) []byte {
	return derWrap(0xa0+number, value)
}

func derGeneralString(value string) []byte {
	return derWrap(0x1b, []byte(value))
}

func derInteger(value int) []byte {
	content := []byte{byte(value)}
	if value > 0xff {
		content = []byte{byte(value >> 8), byte(value)}
	}
	if content[0]&0x80 != 0 {
		content = append([]byte{0}, content...)
	}
	return derWrap(0x02, content)
}

func derWrap(tag byte, content []byte) []byte {
	encoded := []byte{tag}
	length := len(content)
	switch {
	case length < 0x80:
		encoded = append(encoded, byte(length))
	case length <= 0xff:
		encoded = append(encoded, 0x81, byte(length))
	default:
		encoded = append(encoded, 0x82, byte(length>>8), byte(length))
	}
	return append(encoded, content...)
}

func joinBytes(values ...[]byte) []byte {
	size := 0
	for _, value := range values {
		size += len(value)
	}
	joined := make([]byte, 0, size)
	for _, value := range values {
		joined = append(joined, value...)
	}
	return joined
}
