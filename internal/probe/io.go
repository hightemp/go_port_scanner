package probe

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

const maxTextLine = 4096

func readLine(reader *bufio.Reader, limit int) (string, error) {
	var line []byte
	for len(line) <= limit {
		fragment, prefix, err := reader.ReadLine()
		line = append(line, fragment...)
		if len(line) > limit {
			return "", fmt.Errorf("protocol line exceeds %d bytes", limit)
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(line) > 0 {
				return string(line), nil
			}
			return "", err
		}
		if !prefix {
			return string(line), nil
		}
	}
	return "", fmt.Errorf("protocol line exceeds %d bytes", limit)
}

func cleanDetail(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return ' '
		}
		return character
	}, value)
	if len(value) > 200 {
		return value[:200] + "..."
	}
	return value
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrUnexpectedEOF
		}
		payload = payload[written:]
	}
	return nil
}
