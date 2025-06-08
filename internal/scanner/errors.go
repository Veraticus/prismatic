package scanner

import (
	"fmt"
)

// ErrorType represents the type of scanner error.
type ErrorType string

const (
	// ErrorTypeConfig indicates a configuration error.
	ErrorTypeConfig ErrorType = "config"
	// ErrorTypeExecution indicates an error during scanner execution.
	ErrorTypeExecution ErrorType = "execution"
	// ErrorTypeParse indicates an error parsing scanner output.
	ErrorTypeParse ErrorType = "parse"
	// ErrorTypeTimeout indicates a scanner timeout.
	ErrorTypeTimeout ErrorType = "timeout"
	// ErrorTypeContext indicates context cancellation.
	ErrorTypeContext ErrorType = "context"
	// ErrorTypeAuth indicates an authentication error.
	ErrorTypeAuth ErrorType = "auth"
)

// ScannerError represents a structured error from a scanner.
type ScannerError struct {
	Err       error
	Scanner   string
	Type      ErrorType
	Message   string
	Retryable bool
}

// Error implements the error interface.
func (e *ScannerError) Error() string {
	return fmt.Sprintf("%s scanner %s error: %s", e.Scanner, e.Type, e.Message)
}

// Unwrap returns the underlying error.
func (e *ScannerError) Unwrap() error {
	return e.Err
}

// NewStructuredError creates a new structured scanner error.
func NewStructuredError(scanner string, errType ErrorType, err error) *ScannerError {
	return &ScannerError{
		Scanner:   scanner,
		Type:      errType,
		Message:   err.Error(),
		Err:       err,
		Retryable: isRetryable(errType),
	}
}

// NewStructuredErrorf creates a new structured scanner error with formatted message.
func NewStructuredErrorf(scanner string, errType ErrorType, format string, args ...interface{}) *ScannerError {
	return &ScannerError{
		Scanner:   scanner,
		Type:      errType,
		Message:   fmt.Sprintf(format, args...),
		Retryable: isRetryable(errType),
	}
}

// isRetryable determines if an error type is retryable.
func isRetryable(errType ErrorType) bool {
	switch errType {
	case ErrorTypeTimeout, ErrorTypeExecution:
		return true
	default:
		return false
	}
}

// IsConfigError checks if the error is a configuration error.
func IsConfigError(err error) bool {
	if e, ok := err.(*ScannerError); ok {
		return e.Type == ErrorTypeConfig
	}
	return false
}

// IsTimeoutError checks if the error is a timeout error.
func IsTimeoutError(err error) bool {
	if e, ok := err.(*ScannerError); ok {
		return e.Type == ErrorTypeTimeout
	}
	return false
}

// IsAuthError checks if the error is an authentication error.
func IsAuthError(err error) bool {
	if e, ok := err.(*ScannerError); ok {
		return e.Type == ErrorTypeAuth
	}
	return false
}

// WrapError wraps an error with scanner context.
func WrapError(scanner string, err error) error {
	if err == nil {
		return nil
	}

	// If it's already a ScannerError, return as-is
	if _, ok := err.(*ScannerError); ok {
		return err
	}

	// Determine error type based on error message
	errType := ErrorTypeExecution
	if err.Error() == "context canceled" || err.Error() == "context deadline exceeded" {
		errType = ErrorTypeContext
	}

	return NewStructuredError(scanner, errType, err)
}

// NewScannerError creates a scanner error for backward compatibility.
// Maps the old phase parameter to new error types.
func NewScannerError(scanner, phase string, err error) error {
	errType := mapPhaseToErrorType(phase)
	return NewStructuredError(scanner, errType, err)
}

// mapPhaseToErrorType maps old phase strings to error types.
func mapPhaseToErrorType(phase string) ErrorType {
	switch phase {
	case "parse":
		return ErrorTypeParse
	case "config":
		return ErrorTypeConfig
	case "auth":
		return ErrorTypeAuth
	case "timeout":
		return ErrorTypeTimeout
	default:
		return ErrorTypeExecution
	}
}
