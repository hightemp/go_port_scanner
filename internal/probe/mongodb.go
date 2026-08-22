package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	mongoRequestID = 1
	mongoOPMsg     = 2013
	maxMongoReply  = 16 << 20
)

type mongodbProbe struct{}

func (mongodbProbe) Name() string { return "mongodb" }

func (mongodbProbe) Probe(_ context.Context, connection net.Conn, _ Target) (string, error) {
	request := mongoHelloRequest()
	if err := writeAll(connection, request); err != nil {
		return "", fmt.Errorf("send MongoDB hello: %w", err)
	}

	header := make([]byte, 16)
	if _, err := io.ReadFull(connection, header); err != nil {
		return "", fmt.Errorf("read MongoDB message header: %w", err)
	}
	length := int(int32(binary.LittleEndian.Uint32(header[0:4])))
	responseTo := int32(binary.LittleEndian.Uint32(header[8:12]))
	opcode := int32(binary.LittleEndian.Uint32(header[12:16]))
	if length < len(header) || length > maxMongoReply {
		return "", fmt.Errorf("invalid MongoDB message length %d", length)
	}
	if responseTo != mongoRequestID {
		return "", fmt.Errorf("unexpected MongoDB response id %d", responseTo)
	}
	if opcode != mongoOPMsg {
		return "", fmt.Errorf("unexpected MongoDB opcode %d", opcode)
	}
	return "OP_MSG hello response", nil
}

func mongoHelloRequest() []byte {
	// BSON: {hello: int32(1), $db: "admin"}.
	document := []byte{
		31, 0, 0, 0,
		0x10, 'h', 'e', 'l', 'l', 'o', 0, 1, 0, 0, 0,
		0x02, '$', 'd', 'b', 0, 6, 0, 0, 0, 'a', 'd', 'm', 'i', 'n', 0,
		0,
	}
	message := make([]byte, 16+4+1+len(document))
	binary.LittleEndian.PutUint32(message[0:4], uint32(len(message)))
	binary.LittleEndian.PutUint32(message[4:8], mongoRequestID)
	binary.LittleEndian.PutUint32(message[12:16], mongoOPMsg)
	message[20] = 0 // OP_MSG kind 0 body section.
	copy(message[21:], document)
	return message
}
