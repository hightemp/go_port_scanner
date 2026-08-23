package probe

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
)

const maxHTTPResponseHeader = 64 << 10

type httpProbe struct{}

func (httpProbe) Name() string { return "http" }

func (httpProbe) Probe(ctx context.Context, connection net.Conn, target Target) (string, error) {
	return probeHTTP(ctx, connection, target, "http")
}

func probeHTTP(
	ctx context.Context,
	connection net.Conn,
	target Target,
	scheme string,
) (string, error) {
	address := net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, scheme+"://"+address+"/", nil)
	if err != nil {
		return "", fmt.Errorf("build %s request: %w", scheme, err)
	}
	request.Header.Set("Connection", "close")
	request.Header.Set("User-Agent", "go-port-scanner")
	if err := request.Write(connection); err != nil {
		return "", fmt.Errorf("send %s request: %w", scheme, err)
	}

	reader := bufio.NewReader(io.LimitReader(connection, maxHTTPResponseHeader))
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return "", fmt.Errorf("read %s response: %w", scheme, err)
	}
	detail := cleanDetail(response.Proto + " " + response.Status)
	if server := cleanDetail(response.Header.Get("Server")); server != "" {
		detail += "; server " + server
	}
	if err := response.Body.Close(); err != nil {
		return "", fmt.Errorf("close %s response: %w", scheme, err)
	}
	return detail, nil
}
