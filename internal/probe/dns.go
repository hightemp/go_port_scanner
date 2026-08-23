package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	dnsTransactionID  = 0x4753
	dnsHeaderSize     = 12
	dnsQuestionOffset = dnsHeaderSize
	dnsRootNSQuestion = "\x00\x00\x02\x00\x01"
)

type dnsProbe struct{}

func (dnsProbe) Name() string { return "dns" }

func (dnsProbe) Probe(_ context.Context, connection net.Conn, _ Target) (string, error) {
	query := dnsRootNSQuery()
	request := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(request[:2], uint16(len(query)))
	copy(request[2:], query)
	if err := writeAll(connection, request); err != nil {
		return "", fmt.Errorf("send DNS-over-TCP query: %w", err)
	}

	var lengthBytes [2]byte
	if _, err := io.ReadFull(connection, lengthBytes[:]); err != nil {
		return "", fmt.Errorf("read DNS-over-TCP response length: %w", err)
	}
	length := int(binary.BigEndian.Uint16(lengthBytes[:]))
	minimumLength := dnsHeaderSize + len(dnsRootNSQuestion)
	if length < minimumLength {
		return "", fmt.Errorf("invalid DNS-over-TCP response length %d", length)
	}

	response := make([]byte, length)
	if _, err := io.ReadFull(connection, response); err != nil {
		return "", fmt.Errorf("read DNS-over-TCP response: %w", err)
	}
	if transactionID := binary.BigEndian.Uint16(response[0:2]); transactionID != dnsTransactionID {
		return "", fmt.Errorf("unexpected DNS transaction id 0x%04x", transactionID)
	}
	flags := binary.BigEndian.Uint16(response[2:4])
	if flags&0x8000 == 0 {
		return "", fmt.Errorf("DNS message is not a response (flags 0x%04x)", flags)
	}
	if opcode := (flags >> 11) & 0x0f; opcode != 0 {
		return "", fmt.Errorf("unexpected DNS opcode %d", opcode)
	}
	if questionCount := binary.BigEndian.Uint16(response[4:6]); questionCount != 1 {
		return "", fmt.Errorf("unexpected DNS question count %d", questionCount)
	}
	questionEnd := dnsQuestionOffset + len(dnsRootNSQuestion)
	if string(response[dnsQuestionOffset:questionEnd]) != dnsRootNSQuestion {
		return "", fmt.Errorf("unexpected DNS response question %x", response[dnsQuestionOffset:questionEnd])
	}

	responseCode := flags & 0x000f
	answerCount := binary.BigEndian.Uint16(response[6:8])
	authorityCount := binary.BigEndian.Uint16(response[8:10])
	additionalCount := binary.BigEndian.Uint16(response[10:12])
	resourceRecordCount := int(answerCount) + int(authorityCount) + int(additionalCount)
	if err := validateDNSResourceRecords(response, questionEnd, resourceRecordCount); err != nil {
		return "", fmt.Errorf("invalid DNS resource records: %w", err)
	}
	return fmt.Sprintf(
		"DNS-over-TCP response (rcode=%s, answers=%d, authority=%d, additional=%d)",
		dnsResponseCodeName(responseCode),
		answerCount,
		authorityCount,
		additionalCount,
	), nil
}

func validateDNSResourceRecords(message []byte, offset, count int) error {
	for record := 0; record < count; record++ {
		nameEnd, err := dnsNameEnd(message, offset)
		if err != nil {
			return fmt.Errorf("record %d name: %w", record+1, err)
		}
		offset = nameEnd
		const fixedRecordSize = 10
		if offset+fixedRecordSize > len(message) {
			return fmt.Errorf("record %d header is truncated", record+1)
		}
		dataLength := int(binary.BigEndian.Uint16(message[offset+8 : offset+10]))
		offset += fixedRecordSize
		if offset+dataLength > len(message) {
			return fmt.Errorf("record %d data is truncated", record+1)
		}
		offset += dataLength
	}
	if offset != len(message) {
		return fmt.Errorf("message has %d trailing bytes", len(message)-offset)
	}
	return nil
}

func dnsNameEnd(message []byte, offset int) (int, error) {
	consumedEnd := -1
	expandedLength := 0
	for steps := 0; steps <= len(message); steps++ {
		if offset >= len(message) {
			return 0, fmt.Errorf("name is truncated at offset %d", offset)
		}
		length := message[offset]
		if length == 0 {
			if consumedEnd >= 0 {
				return consumedEnd, nil
			}
			return offset + 1, nil
		}
		if length&0xc0 == 0xc0 {
			if offset+1 >= len(message) {
				return 0, fmt.Errorf("compression pointer is truncated at offset %d", offset)
			}
			pointer := int(length&0x3f)<<8 | int(message[offset+1])
			if pointer >= offset {
				return 0, fmt.Errorf("compression pointer %d does not point backwards from %d", pointer, offset)
			}
			if consumedEnd < 0 {
				consumedEnd = offset + 2
			}
			offset = pointer
			continue
		}
		if length&0xc0 != 0 {
			return 0, fmt.Errorf("unsupported label type 0x%02x at offset %d", length, offset)
		}
		offset++
		labelLength := int(length)
		if offset+labelLength > len(message) {
			return 0, fmt.Errorf("label is truncated at offset %d", offset-1)
		}
		expandedLength += labelLength + 1
		if expandedLength > 254 {
			return 0, fmt.Errorf("expanded name exceeds 255 bytes")
		}
		offset += labelLength
	}
	return 0, fmt.Errorf("compression pointer chain is too long")
}

func dnsRootNSQuery() []byte {
	query := make([]byte, dnsHeaderSize+len(dnsRootNSQuestion))
	binary.BigEndian.PutUint16(query[0:2], dnsTransactionID)
	binary.BigEndian.PutUint16(query[4:6], 1)
	copy(query[dnsQuestionOffset:], dnsRootNSQuestion)
	return query
}

func dnsResponseCodeName(code uint16) string {
	switch code {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", code)
	}
}
