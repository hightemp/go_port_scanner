package config

import (
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDecode(t *testing.T) {
	t.Parallel()

	yamlConfig := `
targets:
  - 127.0.0.1
  - example.com
ports:
  - 22
  - 80-82
  - 81-83
scanner:
  workers: 25
  dial_timeout: 250ms
  scan_timeout: 30s
  verbosity: debug
proxy:
  enabled: true
  strategy: random
  tls_insecure_skip_verify: true
  urls:
    - http://proxy.example.com:8080
    - socks5://127.0.0.1:1080
probes:
  enabled: true
  timeout: 900ms
  tls_insecure_skip_verify: true
  ssh:
    enabled: true
    ports: [22, 2200-2201]
  ftp:
    enabled: false
`

	got, err := Decode(strings.NewReader(yamlConfig))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	wantTargets := []string{"127.0.0.1", "example.com"}
	if !reflect.DeepEqual(got.Targets, wantTargets) {
		t.Errorf("Targets = %v, want %v", got.Targets, wantTargets)
	}
	wantPorts := []int{22, 80, 81, 82, 83}
	if ports := got.ExpandedPorts(); !reflect.DeepEqual(ports, wantPorts) {
		t.Errorf("ExpandedPorts() = %v, want %v", ports, wantPorts)
	}
	if got.Scanner.Workers != 25 {
		t.Errorf("Workers = %d, want 25", got.Scanner.Workers)
	}
	if got.Scanner.DialTimeout.Duration != 250*time.Millisecond {
		t.Errorf("DialTimeout = %v, want 250ms", got.Scanner.DialTimeout.Duration)
	}
	if got.Scanner.ScanTimeout.Duration != 30*time.Second {
		t.Errorf("ScanTimeout = %v, want 30s", got.Scanner.ScanTimeout.Duration)
	}
	if got.VerbosityLevel() != 2 {
		t.Errorf("VerbosityLevel() = %d, want 2", got.VerbosityLevel())
	}
	if !got.Proxy.Enabled || got.Proxy.Strategy != ProxyStrategyRandom ||
		!got.Proxy.TLSInsecureSkipVerify || len(got.Proxy.URLs) != 2 {
		t.Errorf("Proxy = %#v, want enabled random pool with two URLs", got.Proxy)
	}
	if !got.Probes.Enabled || got.Probes.Timeout.Duration != 900*time.Millisecond ||
		!got.Probes.TLSInsecureSkipVerify || got.Probes.FTP.Enabled {
		t.Errorf("Probes = %#v, want enabled probes with FTP disabled", got.Probes)
	}
	definitions := got.EnabledProbeDefinitions()
	if len(definitions) != 16 || definitions[0].Name != "ssh" ||
		!reflect.DeepEqual(definitions[0].Ports, []int{22, 2200, 2201}) {
		t.Errorf("EnabledProbeDefinitions() = %#v", definitions)
	}
}

func TestDecodeUsesDefaults(t *testing.T) {
	t.Parallel()

	got, err := Decode(strings.NewReader("scanner:\n  workers: 5\n"))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	want := Default()
	want.Scanner.Workers = 5
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Decode() = %#v, want %#v", got, want)
	}
}

func TestDecodeValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		yaml string
	}{
		{name: "unknown field", yaml: "unknown: true\n"},
		{name: "empty targets", yaml: "targets: []\n"},
		{name: "empty target", yaml: "targets: ['']\n"},
		{name: "empty ports", yaml: "ports: []\n"},
		{name: "zero port", yaml: "ports: [0]\n"},
		{name: "high port", yaml: "ports: [65536]\n"},
		{name: "reversed range", yaml: "ports: [100-80]\n"},
		{name: "invalid range", yaml: "ports: [one-two]\n"},
		{name: "zero workers", yaml: "scanner: {workers: 0}\n"},
		{name: "zero dial timeout", yaml: "scanner: {dial_timeout: 0s}\n"},
		{name: "negative scan timeout", yaml: "scanner: {scan_timeout: -1s}\n"},
		{name: "unknown verbosity", yaml: "scanner: {verbosity: verbose}\n"},
		{name: "enabled proxy without URLs", yaml: "proxy: {enabled: true}\n"},
		{name: "empty proxy URL", yaml: "proxy: {urls: ['']}\n"},
		{name: "unknown proxy strategy", yaml: "proxy: {strategy: first}\n"},
		{name: "zero probe timeout", yaml: "probes: {timeout: 0s}\n"},
		{name: "enabled probe without ports", yaml: "probes: {ssh: {ports: []}}\n"},
		{name: "invalid probe port", yaml: "probes: {ssh: {ports: [65536]}}\n"},
		{name: "multiple documents", yaml: "---\nscanner: {workers: 1}\n---\nscanner: {workers: 2}\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := Decode(strings.NewReader(tt.yaml)); err == nil {
				t.Fatal("Decode() error = nil, want validation error")
			}
		})
	}
}

func TestEnabledProbeDefinitionsDisabled(t *testing.T) {
	t.Parallel()

	configuration := Default()
	if got := configuration.EnabledProbeDefinitions(); got != nil {
		t.Errorf("EnabledProbeDefinitions() = %v, want nil", got)
	}
}

func TestParsePortRange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		want  PortRange
	}{
		{name: "single", value: "443", want: PortRange{Start: 443, End: 443}},
		{name: "range", value: " 8000 - 8010 ", want: PortRange{Start: 8000, End: 8010}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParsePortRange(tt.value)
			if err != nil {
				t.Fatalf("ParsePortRange() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("ParsePortRange() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	t.Parallel()

	path := t.TempDir() + "/config.yaml"
	if err := os.WriteFile(path, []byte("ports: [443]\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if ports := got.ExpandedPorts(); !reflect.DeepEqual(ports, []int{443}) {
		t.Errorf("ExpandedPorts() = %v, want [443]", ports)
	}
}

func TestExampleConfiguration(t *testing.T) {
	t.Parallel()

	configuration, err := Load("../../config.example.yaml")
	if err != nil {
		t.Fatalf("Load(config.example.yaml) error = %v", err)
	}
	if configuration.Probes.Enabled {
		t.Fatal("example protocol probes are enabled, want safe disabled default")
	}
	if !configuration.Probes.SSH.Enabled || !configuration.Probes.FTPSExplicit.Enabled {
		t.Errorf("example protocol switches = %#v, want SSH and FTPS explicit enabled", configuration.Probes)
	}
}
