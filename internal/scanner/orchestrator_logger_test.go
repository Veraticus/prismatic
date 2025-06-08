package scanner

import (
	"context"
	"testing"

	"github.com/Veraticus/prismatic/internal/config"
	"github.com/Veraticus/prismatic/pkg/logger"
)

func TestOrchestratorWithLogger(t *testing.T) {
	// Create a mock logger
	mockLogger := logger.NewMockLogger()

	// Create test config
	cfg := &config.Config{
		Client: config.ClientConfig{
			Name:        "test-client",
			Environment: "test",
		},
	}

	// Create orchestrator with mock logger
	orchestrator := NewOrchestratorWithLogger(cfg, "/tmp/test", true, mockLogger)

	// Initialize scanners - it will use mock scanner since useMock is true
	err := orchestrator.InitializeScanners([]string{"trivy"})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Since we're using mock scanners, we should see initialization messages
	if !mockLogger.HasMessageContaining("DEBUG", "Initialized scanner") {
		t.Error("Expected debug message about initialized scanner")
		t.Logf("Messages: %s", mockLogger.String())
	}
}

func TestScannerFactoryWithLogger(t *testing.T) {
	// Create a mock logger
	mockLogger := logger.NewMockLogger()

	// Create scanner factory with mock logger
	factory := NewScannerFactoryWithLogger(
		Config{},
		&mockClientConfig{},
		"/tmp/test",
		false,
		mockLogger,
	)

	// Try to create a scanner without config
	_, err := factory.CreateScanner("trivy")
	if err == nil {
		t.Error("Expected error creating Trivy scanner without targets")
	}

	// Check that warning was logged
	if !mockLogger.HasMessageContaining("WARN", "No targets configured for Trivy") {
		t.Error("Expected warning about no Trivy targets")
	}
}

// mockClientConfig implements ClientConfig for testing.
type mockClientConfig struct{}

func (m *mockClientConfig) GetAWSConfig() ([]string, []string, []string) {
	return nil, nil, nil
}

func (m *mockClientConfig) GetDockerTargets() []string {
	return nil
}

func (m *mockClientConfig) GetKubernetesConfig() ([]string, []string) {
	return nil, nil
}

func (m *mockClientConfig) GetEndpoints() []string {
	return nil
}

func (m *mockClientConfig) GetCheckovTargets() []string {
	return nil
}

func TestScannerWithLogger(t *testing.T) {
	// Create a mock logger
	mockLogger := logger.NewMockLogger()

	// Test Mock scanner with logger (since we can't run real scanners in tests)
	mockScanner := NewMockScannerWithLogger("prowler", Config{Debug: true}, mockLogger)

	// Run scan
	ctx := context.Background()
	result, err := mockScanner.Scan(ctx)
	if err != nil {
		t.Errorf("Unexpected error from mock scan: %v", err)
	}

	// Verify we got findings
	if len(result.Findings) == 0 {
		t.Error("Expected findings from mock scanner")
	}
}
