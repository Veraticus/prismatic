// Package logger provides structured logging for Prismatic.
package logger

import (
	"context"
	"log/slog"
	"os"
)

// Logger is the global logger instance.
var Logger *slog.Logger

func init() {
	// Initialize with default text handler
	Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
}

// SetupLogger configures the global logger.
func SetupLogger(debug bool, format string) {
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

	Logger = slog.New(handler)
}

// WithContext returns a logger with context values.
func WithContext(ctx context.Context) *slog.Logger {
	return Logger.With("trace_id", ctx.Value("trace_id"))
}

// Debug logs a debug message.
func Debug(msg string, args ...any) {
	Logger.Debug(msg, args...)
}

// Info logs an info message.
func Info(msg string, args ...any) {
	Logger.Info(msg, args...)
}

// Warn logs a warning message.
func Warn(msg string, args ...any) {
	Logger.Warn(msg, args...)
}

// Error logs an error message.
func Error(msg string, args ...any) {
	Logger.Error(msg, args...)
}

// WithScanner returns a logger with scanner context.
func WithScanner(scanner string) *slog.Logger {
	return Logger.With("scanner", scanner)
}

// WithClient returns a logger with client context.
func WithClient(client, environment string) *slog.Logger {
	return Logger.With("client", client, "environment", environment)
}
