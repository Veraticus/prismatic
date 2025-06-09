package scanner

import "github.com/Veraticus/prismatic/pkg/logger"

// MockFactory creates mock scanners for testing.
type MockFactory struct {
	logger logger.Logger
	config Config
}

// NewMockScannerFactory creates a new mock scanner factory.
func NewMockScannerFactory(config Config, log logger.Logger) *MockFactory {
	return &MockFactory{
		config: config,
		logger: log,
	}
}

// CreateScanner creates a mock scanner of the given type.
func (f *MockFactory) CreateScanner(scannerType string) (Scanner, error) {
	return NewMockScannerWithLogger(scannerType, f.config, f.logger), nil
}
