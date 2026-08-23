package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/hightemp/go_port_scanner/internal/scanner"
)

func formatOpenEvent(event scanner.Event, includeHost bool, hostname string) string {
	target := strconv.Itoa(event.Port)
	if includeHost || hostname != "" {
		target = net.JoinHostPort(event.Host, target)
	}
	if hostname != "" {
		target += " (" + hostname + ")"
	}
	if len(event.Probes) == 0 {
		return "TCP: " + target
	}

	results := make([]string, 0, len(event.Probes))
	for _, result := range event.Probes {
		if result.Err != nil {
			results = append(results, fmt.Sprintf("%s: failed (%v)", result.Protocol, result.Err))
			continue
		}
		if result.Detail == "" {
			results = append(results, result.Protocol+": ok")
			continue
		}
		results = append(results, fmt.Sprintf("%s: %s", result.Protocol, result.Detail))
	}
	return fmt.Sprintf("TCP: %s [%s]", target, strings.Join(results, "; "))
}
