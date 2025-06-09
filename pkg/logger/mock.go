package logger

import (
	"fmt"
	"sync"
)

// MockLogger is a logger implementation for testing.
type MockLogger struct {
	Messages *[]LogMessage
	attrs    []any
	mu       sync.Mutex
}

// LogMessage represents a logged message for testing.
type LogMessage struct {
	Level string
	Msg   string
	Args  []any
}

// NewMockLogger creates a new mock logger for testing.
func NewMockLogger() *MockLogger {
	messages := make([]LogMessage, 0)
	return &MockLogger{
		Messages: &messages,
	}
}

// Debug logs a debug message.
func (m *MockLogger) Debug(msg string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	*m.Messages = append(*m.Messages, LogMessage{Level: "DEBUG", Msg: msg, Args: m.mergeAttrs(args)})
}

// Info logs an info message.
func (m *MockLogger) Info(msg string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	*m.Messages = append(*m.Messages, LogMessage{Level: "INFO", Msg: msg, Args: m.mergeAttrs(args)})
}

// Warn logs a warning message.
func (m *MockLogger) Warn(msg string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	*m.Messages = append(*m.Messages, LogMessage{Level: "WARN", Msg: msg, Args: m.mergeAttrs(args)})
}

// Error logs an error message.
func (m *MockLogger) Error(msg string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	*m.Messages = append(*m.Messages, LogMessage{Level: "ERROR", Msg: msg, Args: m.mergeAttrs(args)})
}

// With returns a new logger with additional attributes.
func (m *MockLogger) With(args ...any) Logger {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Copy existing attributes
	newAttrs := make([]any, len(m.attrs)+len(args))
	copy(newAttrs, m.attrs)
	copy(newAttrs[len(m.attrs):], args)

	newLogger := &MockLogger{
		Messages: m.Messages, // Share the same slice
		attrs:    newAttrs,
	}
	return newLogger
}

// WithGroup returns a new logger with a named group.
func (m *MockLogger) WithGroup(name string) Logger {
	return m.With("group", name)
}

// mergeAttrs merges the logger's attributes with the provided args.
func (m *MockLogger) mergeAttrs(args []any) []any {
	if len(m.attrs) == 0 {
		return args
	}
	merged := make([]any, 0, len(m.attrs)+len(args))
	merged = append(merged, m.attrs...)
	merged = append(merged, args...)
	return merged
}

// HasMessage checks if a message with the given level and message exists.
func (m *MockLogger) HasMessage(level, msg string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, lm := range *m.Messages {
		if lm.Level == level && lm.Msg == msg {
			return true
		}
	}
	return false
}

// HasMessageContaining checks if a message with the given level containing the substring exists.
func (m *MockLogger) HasMessageContaining(level, substring string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, lm := range *m.Messages {
		if lm.Level == level && containsString(lm.Msg, substring) {
			return true
		}
	}
	return false
}

// Clear clears all logged messages.
func (m *MockLogger) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	*m.Messages = make([]LogMessage, 0)
}

// String returns a string representation of all logged messages.
func (m *MockLogger) String() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result string
	for _, msg := range *m.Messages {
		result += fmt.Sprintf("[%s] %s %v\n", msg.Level, msg.Msg, msg.Args)
	}
	return result
}

func containsString(str, substr string) bool {
	return len(str) >= len(substr) && (str == substr || substr == "" ||
		(str != "" && substr != "" && str[0:len(substr)] == substr) ||
		(len(str) > len(substr) && containsString(str[1:], substr)))
}
