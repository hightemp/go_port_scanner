package discovery

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func TestICMPPingerEcho(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                string
		target              string
		wantNetwork         string
		wantDestinationType any
	}{
		{
			name:                "IPv4",
			target:              "192.0.2.10",
			wantNetwork:         "udp4",
			wantDestinationType: &net.UDPAddr{},
		},
		{
			name:                "IPv6",
			target:              "2001:db8::10",
			wantNetwork:         "udp6",
			wantDestinationType: &net.UDPAddr{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			connection := &fakePacketConnection{echoReply: true}
			var gotNetwork string
			pinger := &icmpPinger{
				listen: func(network, _ string) (packetConnection, error) {
					gotNetwork = network
					return connection, nil
				},
				lookup: unexpectedLookup,
			}
			alive, err := pinger.Ping(context.Background(), tt.target, time.Second)
			if err != nil {
				t.Fatalf("Ping() error = %v", err)
			}
			if !alive {
				t.Fatal("Ping() alive = false, want true")
			}
			if gotNetwork != tt.wantNetwork {
				t.Errorf("listen network = %q, want %q", gotNetwork, tt.wantNetwork)
			}
			if reflect.TypeOf(connection.destination) != reflect.TypeOf(tt.wantDestinationType) {
				t.Errorf("destination type = %T, want %T", connection.destination, tt.wantDestinationType)
			}
		})
	}
}

func TestICMPPingerResolvesHostname(t *testing.T) {
	t.Parallel()

	connection := &fakePacketConnection{echoReply: true}
	var lookupTarget string
	var events []Event
	pinger := &icmpPinger{
		listen: func(string, string) (packetConnection, error) {
			return connection, nil
		},
		lookup: func(_ context.Context, network, target string) ([]netip.Addr, error) {
			if network != "ip" {
				t.Errorf("lookup network = %q, want ip", network)
			}
			lookupTarget = target
			return []netip.Addr{netip.MustParseAddr("192.0.2.20")}, nil
		},
		report: func(event Event) {
			events = append(events, event)
		},
	}
	alive, err := pinger.Ping(context.Background(), "host.example", time.Second)
	if err != nil || !alive {
		t.Fatalf("Ping() = %v, %v; want true, nil", alive, err)
	}
	if lookupTarget != "host.example" {
		t.Errorf("lookup target = %q, want host.example", lookupTarget)
	}
	if len(events) != 1 || events[0].Kind != EventResolution ||
		!reflect.DeepEqual(events[0].Addresses, []string{"192.0.2.20"}) {
		t.Errorf("resolution events = %#v", events)
	}
}

func TestICMPPingerRawFallback(t *testing.T) {
	t.Parallel()

	connection := &fakePacketConnection{echoReply: true}
	var networks []string
	pinger := &icmpPinger{
		listen: func(network, _ string) (packetConnection, error) {
			networks = append(networks, network)
			if network == "udp4" {
				return nil, errors.New("datagram unavailable")
			}
			return connection, nil
		},
		lookup: unexpectedLookup,
	}
	alive, err := pinger.Ping(context.Background(), "192.0.2.30", time.Second)
	if err != nil || !alive {
		t.Fatalf("Ping() = %v, %v; want true, nil", alive, err)
	}
	if !reflect.DeepEqual(networks, []string{"udp4", "ip4:icmp"}) {
		t.Errorf("listen networks = %v, want [udp4 ip4:icmp]", networks)
	}
	if _, ok := connection.destination.(*net.IPAddr); !ok {
		t.Errorf("destination = %T, want *net.IPAddr", connection.destination)
	}
}

func TestICMPPingerErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		configure func(*icmpPinger, *fakePacketConnection)
		target    string
		wantAlive bool
		wantError string
	}{
		{
			name: "resolution error",
			configure: func(pinger *icmpPinger, _ *fakePacketConnection) {
				pinger.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
					return nil, errors.New("DNS failed")
				}
			},
			target:    "host.example",
			wantError: "DNS failed",
		},
		{
			name: "empty resolution",
			configure: func(pinger *icmpPinger, _ *fakePacketConnection) {
				pinger.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
					return nil, nil
				}
			},
			target:    "host.example",
			wantError: "no addresses",
		},
		{
			name: "socket errors",
			configure: func(pinger *icmpPinger, _ *fakePacketConnection) {
				pinger.listen = func(string, string) (packetConnection, error) {
					return nil, errors.New("socket failed")
				}
			},
			target:    "192.0.2.40",
			wantError: "privileged ip4:icmp",
		},
		{
			name: "deadline error",
			configure: func(_ *icmpPinger, connection *fakePacketConnection) {
				connection.deadlineErr = errors.New("deadline failed")
			},
			target:    "192.0.2.40",
			wantError: "set ICMP deadline",
		},
		{
			name: "write error",
			configure: func(_ *icmpPinger, connection *fakePacketConnection) {
				connection.writeErr = errors.New("write failed")
			},
			target:    "192.0.2.40",
			wantError: "send ICMP",
		},
		{
			name: "read error",
			configure: func(_ *icmpPinger, connection *fakePacketConnection) {
				connection.readErr = errors.New("read failed")
			},
			target:    "192.0.2.40",
			wantError: "read ICMP",
		},
		{
			name: "parse error",
			configure: func(_ *icmpPinger, connection *fakePacketConnection) {
				connection.invalidReply = true
			},
			target:    "192.0.2.40",
			wantError: "parse ICMP",
		},
		{
			name: "timeout means unavailable",
			configure: func(_ *icmpPinger, connection *fakePacketConnection) {
				connection.readErr = testTimeoutError{}
			},
			target: "192.0.2.40",
		},
		{
			name: "close error is reported with alive result",
			configure: func(_ *icmpPinger, connection *fakePacketConnection) {
				connection.echoReply = true
				connection.closeErr = errors.New("close failed")
			},
			target:    "192.0.2.40",
			wantAlive: true,
			wantError: "close ICMP socket",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			connection := &fakePacketConnection{}
			pinger := &icmpPinger{
				listen: func(string, string) (packetConnection, error) {
					return connection, nil
				},
				lookup: unexpectedLookup,
			}
			tt.configure(pinger, connection)
			alive, err := pinger.Ping(context.Background(), tt.target, time.Second)
			if alive != tt.wantAlive {
				t.Errorf("Ping() alive = %v, want %v", alive, tt.wantAlive)
			}
			if tt.wantError == "" {
				if err != nil {
					t.Errorf("Ping() error = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Errorf("Ping() error = %v, want it to contain %q", err, tt.wantError)
			}
		})
	}
}

func TestICMPPingerCancelled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	pinger := &icmpPinger{
		listen: func(string, string) (packetConnection, error) {
			t.Fatal("listen called after cancellation")
			return nil, nil
		},
		lookup: unexpectedLookup,
	}
	if alive, err := pinger.Ping(ctx, "192.0.2.50", time.Second); alive || !errors.Is(err, context.Canceled) {
		t.Fatalf("Ping() = %v, %v; want false, context.Canceled", alive, err)
	}
}

func unexpectedLookup(context.Context, string, string) ([]netip.Addr, error) {
	return nil, errors.New("unexpected lookup")
}

type fakePacketConnection struct {
	mu           sync.Mutex
	destination  net.Addr
	reply        []byte
	echoReply    bool
	invalidReply bool
	deadlineErr  error
	writeErr     error
	readErr      error
	closeErr     error
}

func (c *fakePacketConnection) WriteTo(buffer []byte, destination net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.destination = destination
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if c.invalidReply {
		c.reply = []byte{1}
		return len(buffer), nil
	}
	if !c.echoReply {
		return len(buffer), nil
	}

	protocol := protocolICMPv4
	replyType := icmp.Type(ipv4.ICMPTypeEchoReply)
	if buffer[0] == byte(ipv6.ICMPTypeEchoRequest) {
		protocol = protocolICMPv6
		replyType = ipv6.ICMPTypeEchoReply
	}
	request, err := icmp.ParseMessage(protocol, buffer)
	if err != nil {
		return 0, err
	}
	echo := request.Body.(*icmp.Echo)
	reply := icmp.Message{
		Type: replyType,
		Body: &icmp.Echo{ID: echo.ID, Seq: echo.Seq, Data: echo.Data},
	}
	c.reply, err = reply.Marshal(nil)
	if err != nil {
		return 0, err
	}
	return len(buffer), nil
}

func (c *fakePacketConnection) ReadFrom(buffer []byte) (int, net.Addr, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.readErr != nil {
		return 0, nil, c.readErr
	}
	if len(c.reply) == 0 {
		return 0, nil, testTimeoutError{}
	}
	return copy(buffer, c.reply), c.destination, nil
}

func (c *fakePacketConnection) SetDeadline(time.Time) error { return c.deadlineErr }
func (c *fakePacketConnection) Close() error                { return c.closeErr }
