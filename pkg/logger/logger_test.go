package logger

import (
	"testing"
)

func TestMockLogger(t *testing.T) {
	// Create a mock logger
	mock := NewMockLogger()

	// Test basic logging
	mock.Info("Test message", "key", "value")
	mock.Debug("Debug message")
	mock.Warn("Warning message")
	mock.Error("Error message", "error", "test error")

	// Verify messages were logged
	if len(*mock.Messages) != 4 {
		t.Errorf("Expected 4 messages, got %d", len(*mock.Messages))
	}

	// Test HasMessage
	if !mock.HasMessage("INFO", "Test message") {
		t.Error("Expected to find INFO message")
	}

	// Test HasMessageContaining
	if !mock.HasMessageContaining("ERROR", "Error") {
		t.Error("Expected to find ERROR message containing 'Error'")
	}

	// Test With
	loggerWithContext := mock.With("user", "test-user")
	loggerWithContext.Info("Context message")

	// The last message should have the context
	lastMsg := (*mock.Messages)[len(*mock.Messages)-1]
	if lastMsg.Msg != "Context message" {
		t.Errorf("Expected context message, got: %s", lastMsg.Msg)
		t.Logf("All messages: %+v", *mock.Messages)
	}

	// Check that context was added to args
	found := false
	for i := 0; i < len(lastMsg.Args)-1; i += 2 {
		if lastMsg.Args[i] == "user" && lastMsg.Args[i+1] == "test-user" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to find user context in args")
	}

	// Test Clear
	mock.Clear()
	if len(*mock.Messages) != 0 {
		t.Error("Expected messages to be cleared")
	}
}

func TestLoggerInterface(_ *testing.T) {
	// Test that both SlogLogger and MockLogger implement the Logger interface
	var _ Logger = &SlogLogger{}
	var _ Logger = &MockLogger{}

	// Test that we can use them interchangeably
	testLogger := func(l Logger) {
		l.Info("test")
		l.Debug("debug")
		l.Warn("warn")
		l.Error("error")
		l.With("key", "value").Info("with context")
	}

	// Should compile and run without errors
	testLogger(NewMockLogger())
	testLogger(NewLogger(false, "text"))
}
