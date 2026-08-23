package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRunVersion(t *testing.T) {
	t.Parallel()

	tests := [][]string{
		{"--version"},
		{"version"},
	}
	for _, args := range tests {
		t.Run(args[0], func(t *testing.T) {
			t.Parallel()
			var output bytes.Buffer
			if err := run(context.Background(), args, &output, &bytes.Buffer{}); err != nil {
				t.Fatalf("run(%q) error = %v", args, err)
			}
			want := applicationName + " " + currentVersion() + "\n"
			if output.String() != want {
				t.Errorf("run(%q) output = %q, want %q", args, output.String(), want)
			}
		})
	}
}

func TestNormalizeVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		value string
		want  string
	}{
		{value: "0.1.2", want: "0.1.2"},
		{value: "v1.2.3", want: "1.2.3"},
		{value: " v2.0.0-rc.1\n", want: "2.0.0-rc.1"},
		{value: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(strings.ReplaceAll(tt.value, "\n", "newline"), func(t *testing.T) {
			t.Parallel()
			if got := normalizeVersion(tt.value); got != tt.want {
				t.Errorf("normalizeVersion(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestRunVersionWriteError(t *testing.T) {
	t.Parallel()

	err := run(context.Background(), []string{"--version"}, mainFailingWriter{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "write version") {
		t.Fatalf("run(--version) error = %v, want write version error", err)
	}
}
