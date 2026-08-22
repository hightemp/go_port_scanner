package proxypool

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewValidation(t *testing.T) {
	t.Parallel()

	valid := Config{
		URLs:     []string{"http://127.0.0.1:8080"},
		Strategy: StrategyRoundRobin,
		Timeout:  time.Second,
	}

	tests := []struct {
		name   string
		change func(*Config)
	}{
		{name: "empty URLs", change: func(config *Config) { config.URLs = nil }},
		{name: "zero timeout", change: func(config *Config) { config.Timeout = 0 }},
		{name: "unknown strategy", change: func(config *Config) { config.Strategy = "first" }},
		{name: "missing host", change: func(config *Config) { config.URLs = []string{"http://"} }},
		{name: "unknown scheme", change: func(config *Config) { config.URLs = []string{"ftp://proxy:21"} }},
		{name: "path", change: func(config *Config) { config.URLs = []string{"http://proxy:80/path"} }},
		{name: "query", change: func(config *Config) { config.URLs = []string{"http://proxy:80?option=1"} }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			config := valid
			tt.change(&config)
			if _, err := New(config); err == nil {
				t.Fatal("New() error = nil, want validation error")
			}
		})
	}
}

func TestNewSupportedSchemesAndDefaultPorts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		proxyURL    string
		wantAddress string
	}{
		{name: "HTTP", proxyURL: "http://proxy.example.com", wantAddress: "proxy.example.com:80"},
		{name: "HTTPS", proxyURL: "https://proxy.example.com", wantAddress: "proxy.example.com:443"},
		{name: "SOCKS alias", proxyURL: "socks://proxy.example.com", wantAddress: "proxy.example.com:1080"},
		{name: "SOCKS5H", proxyURL: "socks5h://proxy.example.com", wantAddress: "proxy.example.com:1080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pool, err := New(Config{
				URLs:     []string{tt.proxyURL},
				Strategy: StrategyRandom,
				Timeout:  time.Second,
			})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if pool.Len() != 1 || pool.Strategy() != StrategyRandom {
				t.Errorf("pool = len %d, strategy %q", pool.Len(), pool.Strategy())
			}
			if got := pool.endpoints[0].address; got != tt.wantAddress {
				t.Errorf("endpoint address = %q, want %q", got, tt.wantAddress)
			}
		})
	}
}

func TestSelectionStrategies(t *testing.T) {
	t.Parallel()

	endpoints := []*endpoint{{}, {}, {}}
	tests := []struct {
		name     string
		strategy Strategy
		want     []int
	}{
		{
			name:     "round robin",
			strategy: StrategyRoundRobin,
			want:     []int{0, 1, 2, 0},
		},
		{
			name:     "least connections balances ties",
			strategy: StrategyLeastConnections,
			want:     []int{0, 1, 2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pool := &Pool{
				endpoints: endpoints,
				strategy:  tt.strategy,
				active:    make([]int, len(endpoints)),
			}
			for _, want := range tt.want {
				if got := pool.acquire(); got != want {
					t.Fatalf("acquire() = %d, want %d", got, want)
				}
			}
		})
	}
}

func TestLeastConnectionsReusesReleasedProxy(t *testing.T) {
	t.Parallel()

	pool := &Pool{
		endpoints: []*endpoint{{}, {}, {}},
		strategy:  StrategyLeastConnections,
		active:    make([]int, 3),
	}
	for range 3 {
		pool.acquire()
	}
	pool.release(1)

	if got := pool.acquire(); got != 1 {
		t.Fatalf("acquire() = %d, want released proxy 1", got)
	}
}

func TestRandomSelectionIsInRange(t *testing.T) {
	t.Parallel()

	pool := &Pool{
		endpoints: []*endpoint{{}, {}, {}},
		strategy:  StrategyRandom,
		active:    make([]int, 3),
	}
	for range 100 {
		index := pool.acquire()
		if index < 0 || index >= len(pool.endpoints) {
			t.Fatalf("acquire() = %d, want index in range", index)
		}
		pool.release(index)
	}
}

func TestRoundRobinConcurrent(t *testing.T) {
	t.Parallel()

	pool := &Pool{
		endpoints: []*endpoint{{}, {}, {}},
		strategy:  StrategyRoundRobin,
		active:    make([]int, 3),
	}
	var workers sync.WaitGroup
	for range 100 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			index := pool.acquire()
			pool.release(index)
		}()
	}
	workers.Wait()

	for index, active := range pool.active {
		if active != 0 {
			t.Errorf("active[%d] = %d, want 0", index, active)
		}
	}
}

func TestHTTPProxyDial(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		start    func(http.Handler) *httptest.Server
		insecure bool
	}{
		{name: "HTTP", start: httptest.NewServer},
		{name: "HTTPS", start: httptest.NewTLSServer, insecure: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			observed := make(chan string, 1)
			server := tt.start(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.Method != http.MethodConnect {
					writer.WriteHeader(http.StatusMethodNotAllowed)
					return
				}
				observed <- request.Host + "|" + request.Header.Get("Proxy-Authorization")
				writer.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			proxyURL, err := url.Parse(server.URL)
			if err != nil {
				t.Fatalf("url.Parse() error = %v", err)
			}
			proxyURL.User = url.UserPassword("alice", "secret")
			pool, err := New(Config{
				URLs:                  []string{proxyURL.String()},
				Strategy:              StrategyRoundRobin,
				Timeout:               time.Second,
				TLSInsecureSkipVerify: tt.insecure,
			})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			connection, err := pool.DialContext(context.Background(), "tcp", "example.com:443")
			if err != nil {
				t.Fatalf("DialContext() error = %v", err)
			}
			if err := connection.Close(); err != nil {
				t.Errorf("connection.Close() error = %v", err)
			}

			select {
			case got := <-observed:
				if want := "example.com:443|Basic YWxpY2U6c2VjcmV0"; got != want {
					t.Errorf("proxy request = %q, want %q", got, want)
				}
			case <-time.After(time.Second):
				t.Fatal("proxy did not receive CONNECT request")
			}
		})
	}
}

func TestHTTPProxyRejectsTunnel(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	pool, err := New(Config{
		URLs:     []string{server.URL},
		Strategy: StrategyRoundRobin,
		Timeout:  time.Second,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := pool.DialContext(context.Background(), "tcp", "example.com:443"); err == nil || !strings.Contains(err.Error(), "403 Forbidden") {
		t.Fatalf("DialContext() error = %v, want proxy status", err)
	}
}

func TestHTTPProxyRejectsUnsupportedNetwork(t *testing.T) {
	t.Parallel()

	pool, err := New(Config{
		URLs:     []string{"http://127.0.0.1:8080"},
		Strategy: StrategyRoundRobin,
		Timeout:  time.Second,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := pool.DialContext(context.Background(), "udp", "example.com:53"); err == nil || !strings.Contains(err.Error(), "unsupported network") {
		t.Fatalf("DialContext() error = %v, want unsupported network", err)
	}
}

func TestHTTPSProxyVerifiesCertificateByDefault(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	pool, err := New(Config{
		URLs:     []string{server.URL},
		Strategy: StrategyRoundRobin,
		Timeout:  time.Second,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := pool.DialContext(context.Background(), "tcp", "example.com:443"); err == nil {
		t.Fatal("DialContext() error = nil, want certificate verification error")
	}
}

func TestSOCKS5ProxyDial(t *testing.T) {
	t.Parallel()

	proxyAddress, target, serverError := startSOCKS5Server(t)
	pool, err := New(Config{
		URLs:     []string{"socks5://" + proxyAddress},
		Strategy: StrategyRoundRobin,
		Timeout:  time.Second,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	connection, err := pool.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	if err := connection.Close(); err != nil {
		t.Errorf("connection.Close() error = %v", err)
	}

	if got := <-target; got != "example.com:443" {
		t.Errorf("SOCKS5 target = %q, want example.com:443", got)
	}
	if err := <-serverError; err != nil {
		t.Fatalf("SOCKS5 server error = %v", err)
	}
}

func startSOCKS5Server(t *testing.T) (string, <-chan string, <-chan error) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("listener.Close() error = %v", err)
		}
	})

	target := make(chan string, 1)
	serverError := make(chan error, 1)
	go func() {
		serverError <- serveSOCKS5(listener, target)
	}()
	return listener.Addr().String(), target, serverError
}

func serveSOCKS5(listener net.Listener, target chan<- string) (resultErr error) {
	connection, err := listener.Accept()
	if err != nil {
		return fmt.Errorf("accept: %w", err)
	}
	defer func() {
		if err := connection.Close(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close connection: %w", err))
		}
	}()

	greeting := make([]byte, 2)
	if _, err := io.ReadFull(connection, greeting); err != nil {
		return fmt.Errorf("read greeting: %w", err)
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(connection, methods); err != nil {
		return fmt.Errorf("read methods: %w", err)
	}
	if _, err := connection.Write([]byte{5, 0}); err != nil {
		return fmt.Errorf("write greeting: %w", err)
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(connection, header); err != nil {
		return fmt.Errorf("read request header: %w", err)
	}
	host, err := readSOCKSHost(connection, header[3])
	if err != nil {
		return err
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(connection, portBytes); err != nil {
		return fmt.Errorf("read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBytes)
	target <- net.JoinHostPort(host, strconv.Itoa(int(port)))

	if _, err := connection.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return fmt.Errorf("write response: %w", err)
	}
	return nil
}

func readSOCKSHost(reader io.Reader, addressType byte) (string, error) {
	var length int
	switch addressType {
	case 1:
		length = net.IPv4len
	case 3:
		value := make([]byte, 1)
		if _, err := io.ReadFull(reader, value); err != nil {
			return "", fmt.Errorf("read hostname length: %w", err)
		}
		length = int(value[0])
	case 4:
		length = net.IPv6len
	default:
		return "", fmt.Errorf("unknown SOCKS5 address type %d", addressType)
	}

	value := make([]byte, length)
	if _, err := io.ReadFull(reader, value); err != nil {
		return "", fmt.Errorf("read host: %w", err)
	}
	if addressType == 1 || addressType == 4 {
		return net.IP(value).String(), nil
	}
	return string(value), nil
}
