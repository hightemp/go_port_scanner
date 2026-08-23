package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestExpandedTargets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		targets []string
		want    []string
	}{
		{
			name: "IPv4 CIDR and overlapping ranges",
			targets: []string{
				"example.com",
				"db-01.example.com",
				"192.0.2.0/30",
				"192.0.2.2-192.0.2.5",
				"192.0.2.5",
			},
			want: []string{
				"example.com",
				"db-01.example.com",
				"192.0.2.0",
				"192.0.2.1",
				"192.0.2.2",
				"192.0.2.3",
				"192.0.2.4",
				"192.0.2.5",
			},
		},
		{
			name:    "short IPv4 range",
			targets: []string{" 198.51.100.10-12 "},
			want:    []string{"198.51.100.10", "198.51.100.11", "198.51.100.12"},
		},
		{
			name:    "IPv6 CIDR and range",
			targets: []string{"2001:db8::/126", "2001:db8::2-2001:db8::4"},
			want: []string{
				"2001:db8::",
				"2001:db8::1",
				"2001:db8::2",
				"2001:db8::3",
				"2001:db8::4",
			},
		},
		{
			name:    "canonical addresses and duplicate hostnames",
			targets: []string{"2001:0db8::1", "2001:db8::1", " host.example ", "host.example"},
			want:    []string{"2001:db8::1", "host.example"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			configuration := Default()
			configuration.Targets = tt.targets
			got, err := configuration.ExpandedTargets()
			if err != nil {
				t.Fatalf("ExpandedTargets() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ExpandedTargets() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExpandedTargetsLimit(t *testing.T) {
	t.Parallel()

	configuration := Default()
	configuration.Targets = []string{"192.0.2.0/29"}
	configuration.Scanner.MaxTargets = 4

	_, err := configuration.ExpandedTargets()
	if err == nil || !strings.Contains(err.Error(), "scanner.max_targets (4)") {
		t.Fatalf("ExpandedTargets() error = %v, want max targets error", err)
	}
}

func TestExpandedTargetsErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target string
		want   string
	}{
		{name: "invalid CIDR", target: "192.0.2.0/99", want: "invalid CIDR"},
		{name: "invalid range end", target: "192.0.2.1-999", want: "last octet"},
		{name: "reversed range", target: "192.0.2.2-192.0.2.1", want: "greater than"},
		{name: "mixed families", target: "192.0.2.1-2001:db8::1", want: "different IP families"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			configuration := Default()
			configuration.Targets = []string{tt.target}
			_, err := configuration.ExpandedTargets()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ExpandedTargets() error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}
