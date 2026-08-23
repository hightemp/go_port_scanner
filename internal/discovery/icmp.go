package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	protocolICMPv4 = 1
	protocolICMPv6 = 58
)

type packetConnection interface {
	Close() error
	ReadFrom(buffer []byte) (int, net.Addr, error)
	SetDeadline(deadline time.Time) error
	WriteTo(buffer []byte, destination net.Addr) (int, error)
}

type icmpPinger struct {
	listen func(network, address string) (packetConnection, error)
	lookup func(ctx context.Context, network, host string) ([]netip.Addr, error)
	seq    atomic.Uint32
}

func newICMPPinger() *icmpPinger {
	return &icmpPinger{
		listen: func(network, address string) (packetConnection, error) {
			return icmp.ListenPacket(network, address)
		},
		lookup: net.DefaultResolver.LookupNetIP,
	}
}

func (p *icmpPinger) Ping(ctx context.Context, target string, timeout time.Duration) (bool, error) {
	addresses, err := p.resolve(ctx, target)
	if err != nil {
		return false, err
	}

	var pingErrors error
	for _, address := range addresses {
		alive, pingErr := p.pingAddress(ctx, address.Unmap(), timeout)
		if alive {
			return true, pingErr
		}
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		pingErrors = errors.Join(pingErrors, pingErr)
	}
	return false, pingErrors
}

func (p *icmpPinger) resolve(ctx context.Context, target string) ([]netip.Addr, error) {
	if address, err := netip.ParseAddr(target); err == nil {
		return []netip.Addr{address}, nil
	}

	addresses, err := p.lookup(ctx, "ip", target)
	if err != nil {
		return nil, fmt.Errorf("resolve ICMP target %q: %w", target, err)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("resolve ICMP target %q: no addresses", target)
	}
	return addresses, nil
}

func (p *icmpPinger) pingAddress(
	ctx context.Context,
	address netip.Addr,
	timeout time.Duration,
) (alive bool, resultErr error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	settings := icmpSettingsFor(address)
	connection, raw, err := p.open(settings)
	if err != nil {
		return false, err
	}
	defer func() {
		if closeErr := connection.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close ICMP socket: %w", closeErr))
		}
	}()

	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return false, fmt.Errorf("set ICMP deadline: %w", err)
	}
	stopCancellation := context.AfterFunc(ctx, func() {
		// Best effort: ReadFrom still has the configured deadline if the socket
		// is concurrently closed before this deadline update is applied.
		_ = connection.SetDeadline(time.Now())
	})
	defer stopCancellation()

	sequence := int(p.seq.Add(1) & 0xffff)
	message := icmp.Message{
		Type: settings.requestType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  sequence,
			Data: []byte("go-port-scanner"),
		},
	}
	payload, err := message.Marshal(nil)
	if err != nil {
		return false, fmt.Errorf("marshal ICMP echo request: %w", err)
	}
	if _, err := connection.WriteTo(payload, settings.destination(raw)); err != nil {
		return false, fmt.Errorf("send ICMP echo request to %s: %w", address, err)
	}

	buffer := make([]byte, 1500)
	for {
		read, _, err := connection.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			if isTimeout(err) {
				return false, nil
			}
			return false, fmt.Errorf("read ICMP reply from %s: %w", address, err)
		}

		reply, err := icmp.ParseMessage(settings.protocol, buffer[:read])
		if err != nil {
			return false, fmt.Errorf("parse ICMP reply from %s: %w", address, err)
		}
		echo, ok := reply.Body.(*icmp.Echo)
		if reply.Type == settings.replyType && ok && echo.Seq == sequence {
			return true, nil
		}
	}
}

type icmpSettings struct {
	datagramNetwork string
	rawNetwork      string
	listenAddress   string
	protocol        int
	requestType     icmp.Type
	replyType       icmp.Type
	address         netip.Addr
}

func icmpSettingsFor(address netip.Addr) icmpSettings {
	if address.Is4() {
		return icmpSettings{
			datagramNetwork: "udp4",
			rawNetwork:      "ip4:icmp",
			listenAddress:   "0.0.0.0",
			protocol:        protocolICMPv4,
			requestType:     ipv4.ICMPTypeEcho,
			replyType:       ipv4.ICMPTypeEchoReply,
			address:         address,
		}
	}
	return icmpSettings{
		datagramNetwork: "udp6",
		rawNetwork:      "ip6:ipv6-icmp",
		listenAddress:   "::",
		protocol:        protocolICMPv6,
		requestType:     ipv6.ICMPTypeEchoRequest,
		replyType:       ipv6.ICMPTypeEchoReply,
		address:         address,
	}
}

func (p *icmpPinger) open(settings icmpSettings) (packetConnection, bool, error) {
	connection, err := p.listen(settings.datagramNetwork, settings.listenAddress)
	if err == nil {
		return connection, false, nil
	}
	datagramError := fmt.Errorf("open unprivileged %s ICMP socket: %w", settings.datagramNetwork, err)

	connection, err = p.listen(settings.rawNetwork, settings.listenAddress)
	if err != nil {
		return nil, false, errors.Join(
			datagramError,
			fmt.Errorf("open privileged %s ICMP socket: %w", settings.rawNetwork, err),
		)
	}
	return connection, true, nil
}

func (s icmpSettings) destination(raw bool) net.Addr {
	ip := net.IP(s.address.AsSlice())
	if raw {
		return &net.IPAddr{IP: ip, Zone: s.address.Zone()}
	}
	return &net.UDPAddr{IP: ip, Zone: s.address.Zone()}
}
