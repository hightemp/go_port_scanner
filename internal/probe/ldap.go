package probe

import (
	"bytes"
	"context"
	"fmt"
	"net"
)

type ldapProbe struct{}

func (ldapProbe) Name() string { return "ldap" }

func (ldapProbe) Probe(_ context.Context, connection net.Conn, _ Target) (string, error) {
	return probeLDAP(connection)
}

func probeLDAP(connection net.Conn) (string, error) {
	request := []byte{
		0x30, 0x0c,
		0x02, 0x01, 0x01,
		0x60, 0x07,
		0x02, 0x01, 0x03,
		0x04, 0x00,
		0x80, 0x00,
	}
	if err := writeAll(connection, request); err != nil {
		return "", fmt.Errorf("send LDAP BindRequest: %w", err)
	}

	tag, message, err := readBERElement(connection, 1<<20)
	if err != nil {
		return "", fmt.Errorf("read LDAP BindResponse: %w", err)
	}
	if tag != 0x30 {
		return "", fmt.Errorf("unexpected LDAP message tag 0x%02x", tag)
	}
	reader := bytes.NewReader(message)
	idTag, messageID, err := readBERElement(reader, 8)
	if err != nil || idTag != 0x02 || len(messageID) != 1 || messageID[0] != 1 {
		return "", fmt.Errorf("invalid LDAP BindResponse message id")
	}
	responseTag, response, err := readBERElement(reader, 1<<20)
	if err != nil || responseTag != 0x61 {
		return "", fmt.Errorf("invalid LDAP BindResponse")
	}
	resultTag, resultCode, err := readBERElement(bytes.NewReader(response), 8)
	if err != nil || resultTag != 0x0a || len(resultCode) != 1 {
		return "", fmt.Errorf("invalid LDAP BindResponse result code")
	}
	return fmt.Sprintf("LDAPv3 BindResponse (result code %d)", resultCode[0]), nil
}
