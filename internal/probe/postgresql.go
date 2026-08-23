package probe

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	postgresqlProtocolVersion     = 3 << 16
	maxPostgreSQLMessageLength    = 1 << 20
	postgresqlProbeUsername       = "go_port_scanner"
	postgresqlAuthenticationOK    = 0
	postgresqlAuthenticationKerb5 = 2
	postgresqlAuthenticationClear = 3
	postgresqlAuthenticationMD5   = 5
	postgresqlAuthenticationSCM   = 6
	postgresqlAuthenticationGSS   = 7
	postgresqlAuthenticationCont  = 8
	postgresqlAuthenticationSSPI  = 9
	postgresqlAuthenticationSASL  = 10
	postgresqlAuthenticationSASLC = 11
	postgresqlAuthenticationSASLF = 12
)

type postgresqlProbe struct {
	tlsInsecureSkipVerify bool
}

func (postgresqlProbe) Name() string { return "postgresql" }

func (p postgresqlProbe) Probe(ctx context.Context, connection net.Conn, target Target) (string, error) {
	request := make([]byte, 8)
	binary.BigEndian.PutUint32(request[0:4], 8)
	binary.BigEndian.PutUint32(request[4:8], 80877103)
	if err := writeAll(connection, request); err != nil {
		return "", fmt.Errorf("send PostgreSQL SSLRequest: %w", err)
	}

	reader := bufio.NewReader(connection)
	response, err := reader.ReadByte()
	if err != nil {
		return "", fmt.Errorf("read PostgreSQL SSL response: %w", err)
	}
	if reader.Buffered() != 0 {
		return "", fmt.Errorf("unexpected data after PostgreSQL SSL response byte")
	}
	postgresConnection := connection
	detail := "SSL not supported"
	switch response {
	case 'S':
		tlsConnection := tlsClient(connection, target.Host, p.tlsInsecureSkipVerify)
		if err := tlsConnection.HandshakeContext(ctx); err != nil {
			return "", fmt.Errorf("PostgreSQL TLS handshake: %w", err)
		}
		postgresConnection = tlsConnection
		detail = "SSL supported"
	case 'N':
	default:
		return "", fmt.Errorf("unexpected PostgreSQL SSL response 0x%02x", response)
	}

	if err := writeAll(postgresConnection, postgresqlStartupMessage()); err != nil {
		return "", fmt.Errorf("send PostgreSQL StartupMessage: %w", err)
	}
	messageType, payload, err := readPostgreSQLMessage(postgresConnection)
	if err != nil {
		return "", fmt.Errorf("read PostgreSQL startup response: %w", err)
	}
	if err := validatePostgreSQLStartupResponse(messageType, payload); err != nil {
		return "", err
	}
	return detail, nil
}

func postgresqlStartupMessage() []byte {
	parameters := []byte("user\x00" + postgresqlProbeUsername + "\x00database\x00" + postgresqlProbeUsername + "\x00\x00")
	message := make([]byte, 8+len(parameters))
	binary.BigEndian.PutUint32(message[0:4], uint32(len(message)))
	binary.BigEndian.PutUint32(message[4:8], postgresqlProtocolVersion)
	copy(message[8:], parameters)
	return message
}

func readPostgreSQLMessage(reader io.Reader) (byte, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(reader, header); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(header[1:5])
	if length < 4 || length > maxPostgreSQLMessageLength {
		return 0, nil, fmt.Errorf("invalid PostgreSQL message length %d", length)
	}
	payload := make([]byte, length-4)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, nil, err
	}
	return header[0], payload, nil
}

func validatePostgreSQLStartupResponse(messageType byte, payload []byte) error {
	switch messageType {
	case 'R':
		return validatePostgreSQLAuthentication(payload)
	case 'E':
		return validatePostgreSQLError(payload)
	case 'v':
		return validatePostgreSQLNegotiation(payload)
	default:
		return fmt.Errorf("unexpected PostgreSQL startup response type 0x%02x", messageType)
	}
}

func validatePostgreSQLAuthentication(payload []byte) error {
	if len(payload) < 4 {
		return fmt.Errorf("short PostgreSQL Authentication response: %d bytes", len(payload))
	}
	authenticationType := binary.BigEndian.Uint32(payload[:4])
	switch authenticationType {
	case postgresqlAuthenticationOK,
		postgresqlAuthenticationKerb5,
		postgresqlAuthenticationClear,
		postgresqlAuthenticationMD5,
		postgresqlAuthenticationSCM,
		postgresqlAuthenticationGSS,
		postgresqlAuthenticationCont,
		postgresqlAuthenticationSSPI,
		postgresqlAuthenticationSASL,
		postgresqlAuthenticationSASLC,
		postgresqlAuthenticationSASLF:
		return nil
	default:
		return fmt.Errorf("unknown PostgreSQL authentication type %d", authenticationType)
	}
}

func validatePostgreSQLError(payload []byte) error {
	if len(payload) < 2 || payload[len(payload)-1] != 0 {
		return fmt.Errorf("malformed PostgreSQL ErrorResponse")
	}
	hasCode := false
	hasMessage := false
	for offset := 0; offset < len(payload)-1; {
		fieldType := payload[offset]
		offset++
		end := offset
		for end < len(payload) && payload[end] != 0 {
			end++
		}
		if end == len(payload) || end == offset {
			return fmt.Errorf("malformed PostgreSQL ErrorResponse field 0x%02x", fieldType)
		}
		switch fieldType {
		case 'C':
			hasCode = true
		case 'M':
			hasMessage = true
		}
		offset = end + 1
	}
	if !hasCode || !hasMessage {
		return fmt.Errorf("PostgreSQL ErrorResponse is missing code or message")
	}
	return nil
}

func validatePostgreSQLNegotiation(payload []byte) error {
	if len(payload) < 8 {
		return fmt.Errorf("short PostgreSQL NegotiateProtocolVersion response: %d bytes", len(payload))
	}
	parameterCount := binary.BigEndian.Uint32(payload[4:8])
	offset := 8
	for index := uint32(0); index < parameterCount; index++ {
		end := offset
		for end < len(payload) && payload[end] != 0 {
			end++
		}
		if end == len(payload) || end == offset {
			return fmt.Errorf("malformed PostgreSQL NegotiateProtocolVersion parameter")
		}
		offset = end + 1
	}
	if offset != len(payload) {
		return fmt.Errorf("unexpected PostgreSQL NegotiateProtocolVersion payload")
	}
	return nil
}
