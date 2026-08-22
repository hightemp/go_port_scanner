// Package proxypool provides a concurrent rotating pool of HTTP, HTTPS, and SOCKS5 proxies.
package proxypool

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	xproxy "golang.org/x/net/proxy"
)

// Strategy controls how the pool selects a proxy for each connection.
type Strategy string

const (
	// StrategyRoundRobin selects proxies sequentially and wraps around.
	StrategyRoundRobin Strategy = "round_robin"
	// StrategyRandom selects a random proxy for every connection.
	StrategyRandom Strategy = "random"
	// StrategyLeastConnections selects the proxy with the fewest active connections.
	StrategyLeastConnections Strategy = "least_connections"
)

// Config contains proxy URLs, selection strategy, and transport settings.
type Config struct {
	URLs                  []string
	Strategy              Strategy
	Timeout               time.Duration
	TLSInsecureSkipVerify bool
}

// Pool selects one configured proxy for every DialContext call.
type Pool struct {
	endpoints []*endpoint
	strategy  Strategy
	timeout   time.Duration

	mu     sync.Mutex
	next   int
	active []int
}

// New validates config and creates a concurrency-safe proxy pool.
func New(config Config) (*Pool, error) {
	if len(config.URLs) == 0 {
		return nil, errors.New("proxy URLs must not be empty")
	}
	if config.Timeout <= 0 {
		return nil, errors.New("proxy timeout must be greater than zero")
	}
	switch config.Strategy {
	case StrategyRoundRobin, StrategyRandom, StrategyLeastConnections:
	default:
		return nil, fmt.Errorf("unsupported proxy strategy %q", config.Strategy)
	}

	baseDialer := &net.Dialer{Timeout: config.Timeout}
	endpoints := make([]*endpoint, 0, len(config.URLs))
	for index, rawURL := range config.URLs {
		parsed, err := newEndpoint(rawURL, baseDialer, config.TLSInsecureSkipVerify)
		if err != nil {
			return nil, fmt.Errorf("proxy URL %d: %w", index, err)
		}
		endpoints = append(endpoints, parsed)
	}

	return &Pool{
		endpoints: endpoints,
		strategy:  config.Strategy,
		timeout:   config.Timeout,
		active:    make([]int, len(endpoints)),
	}, nil
}

// Len returns the number of proxies in the pool.
func (p *Pool) Len() int {
	return len(p.endpoints)
}

// Strategy returns the configured proxy selection strategy.
func (p *Pool) Strategy() Strategy {
	return p.strategy
}

// DialContext selects a proxy and establishes a tunnel to address.
func (p *Pool) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialContext, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	index := p.acquire()
	connection, err := p.endpoints[index].dialContext(dialContext, network, address)
	if err != nil {
		p.release(index)
		return nil, fmt.Errorf("dial through proxy %s: %w", p.endpoints[index].label, err)
	}
	if err := dialContext.Err(); err != nil {
		closeErr := connection.Close()
		p.release(index)
		if closeErr != nil {
			return nil, errors.Join(err, fmt.Errorf("close canceled proxy connection: %w", closeErr))
		}
		return nil, err
	}

	return &trackedConn{
		Conn: connection,
		release: func() {
			p.release(index)
		},
	}, nil
}

func (p *Pool) acquire() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	var index int
	switch p.strategy {
	case StrategyRandom:
		index = rand.IntN(len(p.endpoints))
	case StrategyLeastConnections:
		index = p.next
		for offset := 1; offset < len(p.endpoints); offset++ {
			candidate := (p.next + offset) % len(p.endpoints)
			if p.active[candidate] < p.active[index] {
				index = candidate
			}
		}
		p.next = (index + 1) % len(p.endpoints)
	default:
		index = p.next
		p.next = (p.next + 1) % len(p.endpoints)
	}
	p.active[index]++
	return index
}

func (p *Pool) release(index int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.active[index] > 0 {
		p.active[index]--
	}
}

type endpoint struct {
	address    string
	label      string
	authHeader string
	baseDialer *net.Dialer
	tlsConfig  *tls.Config
	socks      xproxy.ContextDialer
}

func newEndpoint(rawURL string, baseDialer *net.Dialer, insecureSkipVerify bool) (*endpoint, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Hostname() == "" {
		return nil, errors.New("proxy host must not be empty")
	}
	if (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("proxy URL must not contain a path, query, or fragment")
	}

	defaultPort := ""
	switch parsed.Scheme {
	case "http":
		defaultPort = "80"
	case "https":
		defaultPort = "443"
	case "socks", "socks5", "socks5h":
		defaultPort = "1080"
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", parsed.Scheme)
	}

	address := parsed.Host
	if parsed.Port() == "" {
		address = net.JoinHostPort(parsed.Hostname(), defaultPort)
	}
	result := &endpoint{
		address:    address,
		label:      parsed.Scheme + "://" + address,
		baseDialer: baseDialer,
	}

	if parsed.User != nil {
		username := parsed.User.Username()
		password := ""
		if configuredPassword, exists := parsed.User.Password(); exists {
			password = configuredPassword
		}
		credentials := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		result.authHeader = "Basic " + credentials
	}

	if parsed.Scheme == "https" {
		result.tlsConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			ServerName:         parsed.Hostname(),
			InsecureSkipVerify: insecureSkipVerify, //nolint:gosec // Explicit opt-in for private HTTPS proxies.
		}
	}
	if parsed.Scheme == "socks" || parsed.Scheme == "socks5" || parsed.Scheme == "socks5h" {
		var auth *xproxy.Auth
		if parsed.User != nil {
			password := ""
			if configuredPassword, exists := parsed.User.Password(); exists {
				password = configuredPassword
			}
			auth = &xproxy.Auth{User: parsed.User.Username(), Password: password}
		}
		socksDialer, err := xproxy.SOCKS5("tcp", address, auth, baseDialer)
		if err != nil {
			return nil, fmt.Errorf("create SOCKS5 dialer: %w", err)
		}
		contextDialer, ok := socksDialer.(xproxy.ContextDialer)
		if !ok {
			return nil, errors.New("SOCKS5 dialer does not support contexts")
		}
		result.socks = contextDialer
	}

	return result, nil
}

func (e *endpoint) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if e.socks != nil {
		return e.socks.DialContext(ctx, network, address)
	}
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("unsupported network %q", network)
	}

	connection, err := e.baseDialer.DialContext(ctx, "tcp", e.address)
	if err != nil {
		return nil, fmt.Errorf("connect to proxy: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return nil, closeWithError(connection, fmt.Errorf("set proxy deadline: %w", err))
		}
	}

	if e.tlsConfig != nil {
		tlsConnection := tls.Client(connection, e.tlsConfig)
		if err := tlsConnection.HandshakeContext(ctx); err != nil {
			return nil, closeWithError(tlsConnection, fmt.Errorf("TLS proxy handshake: %w", err))
		}
		connection = tlsConnection
	}

	watcher := watchCancellation(ctx, connection)
	request := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: address},
		Host:   address,
		Header: make(http.Header),
	}
	request.Header.Set("User-Agent", "go_port_scanner")
	if e.authHeader != "" {
		request.Header.Set("Proxy-Authorization", e.authHeader)
	}
	if err := request.Write(connection); err != nil {
		return nil, watcher.closeWithError(connection, fmt.Errorf("write CONNECT request: %w", err))
	}

	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, watcher.closeWithError(connection, fmt.Errorf("read CONNECT response: %w", err))
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		statusErr := fmt.Errorf("proxy CONNECT returned %s", response.Status)
		if response.Body != nil {
			if err := response.Body.Close(); err != nil {
				statusErr = errors.Join(statusErr, fmt.Errorf("close CONNECT response: %w", err))
			}
		}
		return nil, watcher.closeWithError(connection, statusErr)
	}

	closed, closeErr := watcher.stopWatching()
	if closed {
		cancelErr := ctx.Err()
		if cancelErr == nil {
			cancelErr = errors.New("proxy connection canceled")
		}
		if closeErr != nil {
			cancelErr = errors.Join(cancelErr, fmt.Errorf("close canceled proxy connection: %w", closeErr))
		}
		return nil, cancelErr
	}
	if err := ctx.Err(); err != nil {
		return nil, closeWithError(connection, err)
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return nil, closeWithError(connection, fmt.Errorf("clear proxy deadline: %w", err))
	}

	return &bufferedConn{Conn: connection, reader: reader}, nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(buffer []byte) (int, error) {
	return c.reader.Read(buffer)
}

type trackedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

type cancellationWatcher struct {
	stop        func() bool
	closeResult <-chan error
}

func watchCancellation(ctx context.Context, connection net.Conn) cancellationWatcher {
	closeResult := make(chan error, 1)
	stop := context.AfterFunc(ctx, func() {
		closeResult <- connection.Close()
	})
	return cancellationWatcher{stop: stop, closeResult: closeResult}
}

func (w cancellationWatcher) stopWatching() (closed bool, closeErr error) {
	if w.stop() {
		return false, nil
	}
	return true, <-w.closeResult
}

func (w cancellationWatcher) closeWithError(connection net.Conn, cause error) error {
	closed, closeErr := w.stopWatching()
	if !closed {
		closeErr = connection.Close()
	}
	if closeErr != nil {
		return errors.Join(cause, fmt.Errorf("close proxy connection: %w", closeErr))
	}
	return cause
}

func closeWithError(connection net.Conn, cause error) error {
	if err := connection.Close(); err != nil {
		return errors.Join(cause, fmt.Errorf("close proxy connection: %w", err))
	}
	return cause
}
