package probe

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
)

type ftpProbe struct{}

func (ftpProbe) Name() string { return "ftp" }

func (ftpProbe) Probe(_ context.Context, connection net.Conn, _ Target) (string, error) {
	code, message, err := readFTPResponse(bufio.NewReader(connection))
	if err != nil {
		return "", fmt.Errorf("read FTP greeting: %w", err)
	}
	if code != 220 {
		return "", fmt.Errorf("unexpected FTP greeting code %d", code)
	}
	return cleanDetail(message), nil
}

func readFTPResponse(reader *bufio.Reader) (int, string, error) {
	first, err := readLine(reader, maxTextLine)
	if err != nil {
		return 0, "", err
	}
	if len(first) < 3 {
		return 0, "", fmt.Errorf("short FTP response %q", cleanDetail(first))
	}
	code, err := strconv.Atoi(first[:3])
	if err != nil {
		return 0, "", fmt.Errorf("invalid FTP response code %q", cleanDetail(first[:3]))
	}
	if len(first) == 3 || first[3] != '-' {
		return code, first, nil
	}

	terminator := first[:3] + " "
	last := first
	for range 100 {
		last, err = readLine(reader, maxTextLine)
		if err != nil {
			return 0, "", err
		}
		if len(last) >= 4 && last[:4] == terminator {
			return code, last, nil
		}
	}
	return 0, "", fmt.Errorf("unterminated multiline FTP response")
}
