package logging

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestLoggerLevels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		level Level
		want  string
	}{
		{name: "results only", level: 0, want: "TCP: 80\n"},
		{name: "info", level: InfoLevel, want: "TCP: 80\n[INFO] info\n"},
		{name: "debug", level: DebugLevel, want: "TCP: 80\n[INFO] info\n[DEBUG] debug\n"},
		{
			name:  "trace",
			level: TraceLevel,
			want:  "TCP: 80\n[INFO] info\n[DEBUG] debug\n[TRACE] trace\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var output bytes.Buffer
			logger := New(&output, tt.level)
			logger.Printf("TCP: %d\n", 80)
			logger.Infof("info\n")
			logger.Debugf("debug\n")
			logger.Tracef("trace\n")

			if got := output.String(); got != tt.want {
				t.Errorf("logger output = %q, want %q", got, tt.want)
			}
			if err := logger.Err(); err != nil {
				t.Errorf("Err() = %v, want nil", err)
			}
		})
	}
}

func TestLoggerStoresWriteError(t *testing.T) {
	t.Parallel()

	logger := New(failingWriter{}, InfoLevel)
	logger.Infof("message")

	if err := logger.Err(); err == nil || !strings.Contains(err.Error(), "write log output") {
		t.Fatalf("Err() = %v, want wrapped write error", err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}
