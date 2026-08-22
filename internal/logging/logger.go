// Package logging provides the scanner's leveled terminal output.
package logging

import (
	"fmt"
	"io"
	"sync"
)

// Level controls how much diagnostic output is written.
type Level int

const (
	// InfoLevel includes scan lifecycle messages.
	InfoLevel Level = 1
	// DebugLevel includes worker and connection details.
	DebugLevel Level = 2
	// TraceLevel includes an event for every checked port.
	TraceLevel Level = 3
)

// Logger writes leveled scanner messages to an output stream.
type Logger struct {
	output io.Writer
	level  Level
	mu     sync.Mutex
	err    error
}

// New constructs a Logger that writes messages enabled by level to output.
func New(output io.Writer, level Level) *Logger {
	return &Logger{output: output, level: level}
}

// Printf writes an unconditionally visible scanner result.
func (l *Logger) Printf(format string, args ...any) {
	l.write("", format, args...)
}

// Infof writes an informational message when info logging is enabled.
func (l *Logger) Infof(format string, args ...any) {
	if l.level >= InfoLevel {
		l.write("[INFO] ", format, args...)
	}
}

// Debugf writes a diagnostic message when debug logging is enabled.
func (l *Logger) Debugf(format string, args ...any) {
	if l.level >= DebugLevel {
		l.write("[DEBUG] ", format, args...)
	}
}

// Tracef writes a per-port message when trace logging is enabled.
func (l *Logger) Tracef(format string, args ...any) {
	if l.level >= TraceLevel {
		l.write("[TRACE] ", format, args...)
	}
}

// Err returns the first error encountered while writing output.
func (l *Logger) Err() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.err
}

func (l *Logger) write(prefix, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.err != nil {
		return
	}
	if _, err := fmt.Fprintf(l.output, prefix+format, args...); err != nil {
		l.err = fmt.Errorf("write log output: %w", err)
	}
}
