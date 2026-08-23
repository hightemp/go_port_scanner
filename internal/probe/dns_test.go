package probe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
)

func TestDNSProbeResponses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		flags      uint16
		answers    uint16
		authority  uint16
		additional uint16
		wantDetail string
	}{
		{
			name:       "successful answer",
			flags:      0x8000,
			answers:    13,
			additional: 1,
			wantDetail: "DNS-over-TCP response (rcode=NOERROR, answers=13, authority=0, additional=1)",
		},
		{
			name:       "refused still identifies DNS",
			flags:      0x8005,
			authority:  1,
			wantDetail: "DNS-over-TCP response (rcode=REFUSED, answers=0, authority=1, additional=0)",
		},
		{
			name:       "unknown response code",
			flags:      0x800f,
			wantDetail: "DNS-over-TCP response (rcode=RCODE15, answers=0, authority=0, additional=0)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := runPipeProbe(t, dnsProbe{}, func(connection net.Conn) error {
				if err := verifyDNSQuery(connection); err != nil {
					return err
				}
				return writeAll(connection, dnsTCPResponse(
					dnsTransactionID,
					tt.flags,
					1,
					tt.answers,
					tt.authority,
					tt.additional,
					[]byte(dnsRootNSQuestion),
				))
			})
			if result.Err != nil || result.Protocol != "dns" || result.Detail != tt.wantDetail {
				t.Fatalf("Run() = %#v, want detail %q", result, tt.wantDetail)
			}
		})
	}
}

func TestDNSProbeRejectsInvalidResponses(t *testing.T) {
	t.Parallel()

	validFlags := uint16(0x8000)
	tests := []struct {
		name      string
		response  []byte
		wantError string
	}{
		{
			name:      "short message",
			response:  []byte{0, dnsHeaderSize},
			wantError: "invalid DNS-over-TCP response length",
		},
		{
			name:      "wrong transaction id",
			response:  dnsTCPResponse(0x1234, validFlags, 1, 0, 0, 0, []byte(dnsRootNSQuestion)),
			wantError: "unexpected DNS transaction id",
		},
		{
			name:      "query instead of response",
			response:  dnsTCPResponse(dnsTransactionID, 0, 1, 0, 0, 0, []byte(dnsRootNSQuestion)),
			wantError: "DNS message is not a response",
		},
		{
			name:      "unexpected opcode",
			response:  dnsTCPResponse(dnsTransactionID, validFlags|(2<<11), 1, 0, 0, 0, []byte(dnsRootNSQuestion)),
			wantError: "unexpected DNS opcode",
		},
		{
			name:      "missing question",
			response:  dnsTCPResponse(dnsTransactionID, validFlags, 0, 0, 0, 0, []byte(dnsRootNSQuestion)),
			wantError: "unexpected DNS question count",
		},
		{
			name: "different question",
			response: dnsTCPResponse(
				dnsTransactionID,
				validFlags,
				1,
				0,
				0,
				0,
				[]byte{0, 0, 1, 0, 1},
			),
			wantError: "unexpected DNS response question",
		},
		{
			name:      "truncated payload",
			response:  append([]byte{0, dnsHeaderSize + byte(len(dnsRootNSQuestion))}, make([]byte, dnsHeaderSize)...),
			wantError: "read DNS-over-TCP response",
		},
		{
			name: "truncated resource record",
			response: truncateDNSFrame(
				dnsTCPResponse(dnsTransactionID, validFlags, 1, 1, 0, 0, []byte(dnsRootNSQuestion)),
				1,
			),
			wantError: "record 1 data is truncated",
		},
		{
			name:      "trailing data",
			response:  appendDNSFrame(dnsTCPResponse(dnsTransactionID, validFlags, 1, 0, 0, 0, []byte(dnsRootNSQuestion)), 0xff),
			wantError: "trailing bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := runPipeProbe(t, dnsProbe{}, func(connection net.Conn) error {
				if err := verifyDNSQuery(connection); err != nil {
					return err
				}
				return writeAll(connection, tt.response)
			})
			if result.Err == nil || !strings.Contains(result.Err.Error(), tt.wantError) {
				t.Fatalf("Run() error = %v, want %q", result.Err, tt.wantError)
			}
		})
	}
}

func TestDNSResponseCodeName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		code uint16
		want string
	}{
		{code: 0, want: "NOERROR"},
		{code: 1, want: "FORMERR"},
		{code: 2, want: "SERVFAIL"},
		{code: 3, want: "NXDOMAIN"},
		{code: 4, want: "NOTIMP"},
		{code: 5, want: "REFUSED"},
		{code: 15, want: "RCODE15"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("rcode_%d", tt.code), func(t *testing.T) {
			t.Parallel()
			if got := dnsResponseCodeName(tt.code); got != tt.want {
				t.Errorf("dnsResponseCodeName(%d) = %q, want %q", tt.code, got, tt.want)
			}
		})
	}
}

func TestDNSNameEnd(t *testing.T) {
	t.Parallel()

	longName := make([]byte, 0, 4*64+1)
	for range 4 {
		longName = append(longName, 63)
		longName = append(longName, bytes.Repeat([]byte{'a'}, 63)...)
	}
	longName = append(longName, 0)

	tests := []struct {
		name      string
		message   []byte
		offset    int
		wantEnd   int
		wantError string
	}{
		{name: "root", message: []byte{0}, wantEnd: 1},
		{name: "labels", message: []byte{3, 'w', 'w', 'w', 0}, wantEnd: 5},
		{name: "compressed root", message: []byte{0, 0xc0, 0}, offset: 1, wantEnd: 3},
		{
			name:    "label followed by pointer",
			message: []byte{3, 'c', 'o', 'm', 0, 3, 'w', 'w', 'w', 0xc0, 0},
			offset:  5,
			wantEnd: 11,
		},
		{name: "offset outside message", message: []byte{0}, offset: 1, wantError: "name is truncated"},
		{name: "truncated pointer", message: []byte{0xc0}, wantError: "compression pointer is truncated"},
		{name: "forward pointer", message: []byte{0xc0, 2, 0}, wantError: "does not point backwards"},
		{name: "unsupported label", message: []byte{0x40}, wantError: "unsupported label type"},
		{name: "truncated label", message: []byte{3, 'a'}, wantError: "label is truncated"},
		{name: "expanded name too long", message: longName, wantError: "exceeds 255 bytes"},
		{name: "pointer cycle", message: []byte{1, 'a', 0xc0, 0}, wantError: "pointer chain is too long"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			end, err := dnsNameEnd(tt.message, tt.offset)
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("dnsNameEnd() error = %v, want %q", err, tt.wantError)
				}
				return
			}
			if err != nil || end != tt.wantEnd {
				t.Errorf("dnsNameEnd() = %d, %v; want %d, nil", end, err, tt.wantEnd)
			}
		})
	}
}

func verifyDNSQuery(connection net.Conn) error {
	var lengthBytes [2]byte
	if _, err := io.ReadFull(connection, lengthBytes[:]); err != nil {
		return err
	}
	query := make([]byte, binary.BigEndian.Uint16(lengthBytes[:]))
	if _, err := io.ReadFull(connection, query); err != nil {
		return err
	}
	if want := dnsRootNSQuery(); !bytes.Equal(query, want) {
		return fmt.Errorf("DNS query = %x, want %x", query, want)
	}
	return nil
}

func dnsTCPResponse(
	transactionID uint16,
	flags uint16,
	questions uint16,
	answers uint16,
	authority uint16,
	additional uint16,
	question []byte,
) []byte {
	message := make([]byte, dnsHeaderSize+len(question))
	binary.BigEndian.PutUint16(message[0:2], transactionID)
	binary.BigEndian.PutUint16(message[2:4], flags)
	binary.BigEndian.PutUint16(message[4:6], questions)
	binary.BigEndian.PutUint16(message[6:8], answers)
	binary.BigEndian.PutUint16(message[8:10], authority)
	binary.BigEndian.PutUint16(message[10:12], additional)
	copy(message[dnsQuestionOffset:], question)
	resourceRecord := []byte{
		0xc0, 0x0c, // Owner name points to the root question.
		0x00, 0x02, // NS record.
		0x00, 0x01, // IN class.
		0x00, 0x00, 0x00, 0x00, // TTL.
		0x00, 0x01, // RDATA length.
		0x00, // Root NS name.
	}
	for range int(answers) + int(authority) + int(additional) {
		message = append(message, resourceRecord...)
	}
	return dnsTCPFrame(message)
}

func dnsTCPFrame(message []byte) []byte {
	framed := make([]byte, 2+len(message))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(message)))
	copy(framed[2:], message)
	return framed
}

func truncateDNSFrame(frame []byte, count int) []byte {
	frame = append([]byte(nil), frame[:len(frame)-count]...)
	binary.BigEndian.PutUint16(frame[:2], uint16(len(frame)-2))
	return frame
}

func appendDNSFrame(frame []byte, values ...byte) []byte {
	frame = append(append([]byte(nil), frame...), values...)
	binary.BigEndian.PutUint16(frame[:2], uint16(len(frame)-2))
	return frame
}
