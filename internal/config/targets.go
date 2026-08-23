package config

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// ExpandedTargets returns unique hostnames and addresses from all configured
// targets in their configured order. CIDR prefixes and inclusive IP ranges are
// expanded into individual addresses.
func (c Config) ExpandedTargets() ([]string, error) {
	targets := make([]string, 0, len(c.Targets))
	seen := make(map[string]struct{}, len(c.Targets))

	add := func(target string) error {
		if _, exists := seen[target]; exists {
			return nil
		}
		if len(targets) >= c.Scanner.MaxTargets {
			return fmt.Errorf(
				"expanded targets exceed scanner.max_targets (%d); narrow targets or increase the limit",
				c.Scanner.MaxTargets,
			)
		}
		seen[target] = struct{}{}
		targets = append(targets, target)
		return nil
	}

	for index, rawTarget := range c.Targets {
		target := strings.TrimSpace(rawTarget)
		if strings.Contains(target, "/") {
			prefix, err := netip.ParsePrefix(target)
			if err != nil {
				return nil, fmt.Errorf("targets[%d] contains invalid CIDR %q: %w", index, target, err)
			}
			if err := addPrefix(prefix.Masked(), add); err != nil {
				return nil, fmt.Errorf("expand targets[%d] %q: %w", index, target, err)
			}
			continue
		}

		if address, err := netip.ParseAddr(target); err == nil {
			if err := add(address.String()); err != nil {
				return nil, fmt.Errorf("expand targets[%d] %q: %w", index, target, err)
			}
			continue
		}

		start, end, isRange, err := parseIPRange(target)
		if err != nil {
			return nil, fmt.Errorf("targets[%d] contains invalid IP range %q: %w", index, target, err)
		}
		if isRange {
			if err := addRange(start, end, add); err != nil {
				return nil, fmt.Errorf("expand targets[%d] %q: %w", index, target, err)
			}
			continue
		}

		if err := add(target); err != nil {
			return nil, fmt.Errorf("expand targets[%d] %q: %w", index, target, err)
		}
	}

	return targets, nil
}

func addPrefix(prefix netip.Prefix, add func(string) error) error {
	for address := prefix.Addr(); prefix.Contains(address); {
		if err := add(address.String()); err != nil {
			return err
		}
		next := address.Next()
		if !next.IsValid() {
			break
		}
		address = next
	}
	return nil
}

func addRange(start, end netip.Addr, add func(string) error) error {
	for address := start; ; {
		if err := add(address.String()); err != nil {
			return err
		}
		if address == end {
			return nil
		}
		address = address.Next()
	}
}

func parseIPRange(target string) (netip.Addr, netip.Addr, bool, error) {
	startValue, endValue, found := strings.Cut(target, "-")
	if !found {
		return netip.Addr{}, netip.Addr{}, false, nil
	}

	start, err := netip.ParseAddr(strings.TrimSpace(startValue))
	if err != nil {
		return netip.Addr{}, netip.Addr{}, false, nil
	}

	endValue = strings.TrimSpace(endValue)
	end, endErr := netip.ParseAddr(endValue)
	if endErr != nil && start.Is4() {
		end, endErr = parseIPv4RangeEnd(start, endValue)
	}
	if endErr != nil {
		return netip.Addr{}, netip.Addr{}, true, fmt.Errorf("parse end address: %w", endErr)
	}
	if start.BitLen() != end.BitLen() {
		return netip.Addr{}, netip.Addr{}, true, fmt.Errorf("start and end addresses use different IP families")
	}
	if start.Zone() != end.Zone() {
		return netip.Addr{}, netip.Addr{}, true, fmt.Errorf("start and end addresses use different IPv6 zones")
	}
	if start.Compare(end) > 0 {
		return netip.Addr{}, netip.Addr{}, true, fmt.Errorf("start address is greater than end address")
	}

	return start, end, true, nil
}

func parseIPv4RangeEnd(start netip.Addr, value string) (netip.Addr, error) {
	lastOctet, err := strconv.Atoi(value)
	if err != nil {
		return netip.Addr{}, err
	}
	if lastOctet < 0 || lastOctet > 255 {
		return netip.Addr{}, fmt.Errorf("last octet must be between 0 and 255")
	}

	bytes := start.As4()
	bytes[3] = byte(lastOctet)
	return netip.AddrFrom4(bytes), nil
}
