package probe

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
)

type etcdProbe struct{}

func (etcdProbe) Name() string { return "etcd" }

func (etcdProbe) Probe(_ context.Context, connection net.Conn, target Target) (string, error) {
	request, err := http.NewRequest(http.MethodGet, "http://"+net.JoinHostPort(target.Host, fmt.Sprint(target.Port))+"/version", nil)
	if err != nil {
		return "", fmt.Errorf("build etcd request: %w", err)
	}
	request.Header.Set("Connection", "close")
	request.Header.Set("User-Agent", "go-port-scanner")
	if err := request.Write(connection); err != nil {
		return "", fmt.Errorf("send etcd version request: %w", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), request)
	if err != nil {
		return "", fmt.Errorf("read etcd response: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected etcd HTTP status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 16<<10))
	if err != nil {
		return "", fmt.Errorf("read etcd response body: %w", err)
	}
	var version struct {
		Server  string `json:"etcdserver"`
		Cluster string `json:"etcdcluster"`
	}
	if err := json.Unmarshal(body, &version); err != nil {
		return "", fmt.Errorf("decode etcd version: %w", err)
	}
	if version.Server == "" {
		return "", fmt.Errorf("etcdserver version is missing")
	}
	return "server " + cleanDetail(version.Server) + ", cluster " + cleanDetail(version.Cluster), nil
}
