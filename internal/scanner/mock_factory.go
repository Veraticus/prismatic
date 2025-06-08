package scanner

import "github.com/Veraticus/prismatic/pkg/logger"

// MockScannerFactory creates mock scanners for testing.
type MockScannerFactory struct {
	logger logger.Logger
	config Config
}

// NewMockScannerFactory creates a new mock scanner factory.
func NewMockScannerFactory(config Config, log logger.Logger) *MockScannerFactory {
	return &MockScannerFactory{
		config: config,
		logger: log,
	}
}

// CreateScanner creates a mock scanner of the given type.
func (f *MockScannerFactory) CreateScanner(scannerType string) (Scanner, error) {
	return NewMockScannerWithLogger(scannerType, f.config, f.logger), nil
}
