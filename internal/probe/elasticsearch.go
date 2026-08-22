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

type elasticsearchProbe struct{}

func (elasticsearchProbe) Name() string { return "elasticsearch" }

func (elasticsearchProbe) Probe(_ context.Context, connection net.Conn, target Target) (string, error) {
	request, err := http.NewRequest(http.MethodGet, "http://"+net.JoinHostPort(target.Host, fmt.Sprint(target.Port))+"/", nil)
	if err != nil {
		return "", fmt.Errorf("build Elasticsearch request: %w", err)
	}
	request.Header.Set("Connection", "close")
	request.Header.Set("User-Agent", "go-port-scanner")
	if err := request.Write(connection); err != nil {
		return "", fmt.Errorf("send Elasticsearch request: %w", err)
	}

	response, err := http.ReadResponse(bufio.NewReader(connection), request)
	if err != nil {
		return "", fmt.Errorf("read Elasticsearch response: %w", err)
	}
	defer response.Body.Close()

	product := response.Header.Get("X-Elastic-Product")
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if readErr != nil {
		return "", fmt.Errorf("read Elasticsearch response body: %w", readErr)
	}
	var metadata struct {
		Name        string `json:"name"`
		ClusterName string `json:"cluster_name"`
		Version     struct {
			Number string `json:"number"`
		} `json:"version"`
	}
	_ = json.Unmarshal(body, &metadata)
	if product != "Elasticsearch" && metadata.ClusterName == "" && metadata.Version.Number == "" {
		return "", fmt.Errorf("response is not identified as Elasticsearch (HTTP %d)", response.StatusCode)
	}
	if metadata.Version.Number != "" {
		return "version " + cleanDetail(metadata.Version.Number), nil
	}
	if metadata.ClusterName != "" {
		return "cluster " + cleanDetail(metadata.ClusterName), nil
	}
	return fmt.Sprintf("HTTP %d; X-Elastic-Product: %s", response.StatusCode, product), nil
}
