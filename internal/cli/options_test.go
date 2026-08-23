package cli

import (
	"io"
	"testing"
	"time"

	"github.com/hightemp/go_port_scanner/internal/config"
)

func TestParse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		want func(t *testing.T, got Options)
	}{
		{
			name: "defaults use YAML",
			want: func(t *testing.T, got Options) {
				if got.ConfigPath != config.DefaultPath {
					t.Errorf("ConfigPath = %q, want %q", got.ConfigPath, config.DefaultPath)
				}
				if got.Host != nil || got.Workers != nil || got.StartPort != nil ||
					got.EndPort != nil || got.DialTimeout != nil || got.ScanTimeout != nil ||
					got.Verbosity != nil || got.ShowVersion {
					t.Errorf("defaults unexpectedly contain overrides: %#v", got)
				}
			},
		},
		{
			name: "all overrides",
			args: []string{
				"-config", "custom.yaml",
				"-host", "127.0.0.1",
				"-workers", "20",
				"-start", "80",
				"-end", "443",
				"-timeout", "250ms",
				"-scan-timeout", "2m",
				"-vv",
			},
			want: func(t *testing.T, got Options) {
				assertEqual(t, "ConfigPath", got.ConfigPath, "custom.yaml")
				assertPointer(t, "Host", got.Host, "127.0.0.1")
				assertPointer(t, "Workers", got.Workers, 20)
				assertPointer(t, "StartPort", got.StartPort, 80)
				assertPointer(t, "EndPort", got.EndPort, 443)
				assertPointer(t, "DialTimeout", got.DialTimeout, 250*time.Millisecond)
				assertPointer(t, "ScanTimeout", got.ScanTimeout, 2*time.Minute)
				assertPointer(t, "Verbosity", got.Verbosity, 2)
			},
		},
		{
			name: "highest verbosity wins",
			args: []string{"-v", "-vv", "-vvv"},
			want: func(t *testing.T, got Options) {
				assertPointer(t, "Verbosity", got.Verbosity, 3)
			},
		},
		{
			name: "one port boundary uses legacy default for other boundary",
			args: []string{"-start", "100"},
			want: func(t *testing.T, got Options) {
				assertPointer(t, "StartPort", got.StartPort, 100)
				assertPointer(t, "EndPort", got.EndPort, 65535)
			},
		},
		{
			name: "version flag",
			args: []string{"--version"},
			want: func(t *testing.T, got Options) {
				if !got.ShowVersion {
					t.Error("ShowVersion = false, want true")
				}
			},
		},
		{
			name: "version command",
			args: []string{"version"},
			want: func(t *testing.T, got Options) {
				if !got.ShowVersion {
					t.Error("ShowVersion = false, want true")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Parse(tt.args, io.Discard)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			tt.want(t, got)
		})
	}
}

func TestParseRejectsUnexpectedPositionalArguments(t *testing.T) {
	t.Parallel()

	tests := [][]string{
		{"scan"},
		{"version", "extra"},
	}
	for _, args := range tests {
		t.Run(args[0], func(t *testing.T) {
			t.Parallel()
			if _, err := Parse(args, io.Discard); err == nil {
				t.Fatalf("Parse(%q) error = nil, want positional argument error", args)
			}
		})
	}
}

func assertPointer[T comparable](t *testing.T, name string, got *T, want T) {
	t.Helper()
	if got == nil {
		t.Fatalf("%s = nil, want %v", name, want)
	}
	assertEqual(t, name, *got, want)
}

func assertEqual[T comparable](t *testing.T, name string, got, want T) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %v, want %v", name, got, want)
	}
}
