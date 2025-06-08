// Package logger provides structured logging for Prismatic.
package logger

import (
	"context"
	"log/slog"
	"os"
)

// Logger defines the interface for logging operations.
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
	With(args ...any) Logger
	WithGroup(name string) Logger
}

// SlogLogger wraps slog.Logger to implement our Logger interface.
type SlogLogger struct {
	logger *slog.Logger
}

// NewSlogLogger creates a new SlogLogger with the given slog.Logger.
func NewSlogLogger(logger *slog.Logger) Logger {
	return &SlogLogger{logger: logger}
}

// Debug logs a debug message.
func (l *SlogLogger) Debug(msg string, args ...any) {
	l.logger.Debug(msg, args...)
}

// Info logs an info message.
func (l *SlogLogger) Info(msg string, args ...any) {
	l.logger.Info(msg, args...)
}

// Warn logs a warning message.
func (l *SlogLogger) Warn(msg string, args ...any) {
	l.logger.Warn(msg, args...)
}

// Error logs an error message.
func (l *SlogLogger) Error(msg string, args ...any) {
	l.logger.Error(msg, args...)
}

// With returns a logger with additional context.
func (l *SlogLogger) With(args ...any) Logger {
	return &SlogLogger{logger: l.logger.With(args...)}
}

// WithGroup returns a logger with a named group.
func (l *SlogLogger) WithGroup(name string) Logger {
	return &SlogLogger{logger: l.logger.WithGroup(name)}
}

// Global logger instance for backward compatibility.
var globalLogger Logger

func init() {
	// Initialize with default text handler
	slogLogger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	globalLogger = NewSlogLogger(slogLogger)
}

// NewLogger creates a new logger with the specified configuration.
func NewLogger(debug bool, format string) Logger {
	var handler slog.Handler

	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	switch format {
	case "json":
		handler = slog.NewJSONHandler(os.Stderr, opts)
	default:
		handler = slog.NewTextHandler(os.Stderr, opts)
	}

	return NewSlogLogger(slog.New(handler))
}

// SetupLogger configures the global logger (for backward compatibility).
func SetupLogger(debug bool, format string) {
	globalLogger = NewLogger(debug, format)
}

// WithContext returns a logger with context values.
func WithContext(ctx context.Context, l Logger) Logger {
	if traceID := ctx.Value("trace_id"); traceID != nil {
		return l.With("trace_id", traceID)
	}
	return l
}

// WithScanner returns a logger with scanner context.
func WithScanner(l Logger, scanner string) Logger {
	return l.With("scanner", scanner)
}

// WithClient returns a logger with client context.
func WithClient(l Logger, client, environment string) Logger {
	return l.With("client", client, "environment", environment)
}

// Global logger functions for backward compatibility.
// These should be deprecated in favor of dependency injection.

// Debug logs a debug message using the global logger.
func Debug(msg string, args ...any) {
	globalLogger.Debug(msg, args...)
}

// Info logs an info message using the global logger.
func Info(msg string, args ...any) {
	globalLogger.Info(msg, args...)
}

// Warn logs a warning message using the global logger.
func Warn(msg string, args ...any) {
	globalLogger.Warn(msg, args...)
}

// Error logs an error message using the global logger.
func Error(msg string, args ...any) {
	globalLogger.Error(msg, args...)
}

// GetGlobalLogger returns the global logger instance.
// This is useful for transitioning from global to dependency injection.
func GetGlobalLogger() Logger {
	return globalLogger
}
