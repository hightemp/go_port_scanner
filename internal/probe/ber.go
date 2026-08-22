package probe

import (
	"fmt"
	"io"
)

func readBERElement(reader io.Reader, limit int) (byte, []byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return 0, nil, err
	}
	length := int(header[1])
	if header[1]&0x80 != 0 {
		lengthBytes := int(header[1] & 0x7f)
		if lengthBytes == 0 || lengthBytes > 4 {
			return 0, nil, fmt.Errorf("unsupported BER length encoding")
		}
		encodedLength := make([]byte, lengthBytes)
		if _, err := io.ReadFull(reader, encodedLength); err != nil {
			return 0, nil, err
		}
		length = 0
		for _, value := range encodedLength {
			length = length<<8 | int(value)
		}
	}
	if length > limit {
		return 0, nil, fmt.Errorf("BER element length %d exceeds limit %d", length, limit)
	}
	content := make([]byte, length)
	if _, err := io.ReadFull(reader, content); err != nil {
		return 0, nil, err
	}
	return header[0], content, nil
}
