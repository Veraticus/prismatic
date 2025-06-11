package llm

import (
	"context"
	"testing"

	"github.com/joshsymonds/prismatic/internal/enrichment"
	"github.com/joshsymonds/prismatic/internal/models"
)

// MockDriver implements the Driver interface for testing.
type MockDriver struct {
	EnrichFunc          func(ctx context.Context, findings []models.Finding, prompt string) ([]enrichment.FindingEnrichment, error)
	GetCapabilitiesFunc func() Capabilities
	EstimateTokensFunc  func(prompt string) (int, error)
	HealthCheckFunc     func(ctx context.Context) error
	ConfigureFunc       func(config map[string]interface{}) error
}

func (m *MockDriver) Enrich(ctx context.Context, findings []models.Finding, prompt string) ([]enrichment.FindingEnrichment, error) {
	if m.EnrichFunc != nil {
		return m.EnrichFunc(ctx, findings, prompt)
	}
	return []enrichment.FindingEnrichment{}, nil
}

func (m *MockDriver) GetCapabilities() Capabilities {
	if m.GetCapabilitiesFunc != nil {
		return m.GetCapabilitiesFunc()
	}
	return Capabilities{
		ModelName:               "mock-model",
		MaxTokensPerRequest:     100000,
		MaxTokensPerResponse:    4096,
		CostPer1KTokens:         0.001,
		SupportsJSONMode:        true,
		SupportsFunctionCalling: false,
	}
}

func (m *MockDriver) EstimateTokens(prompt string) (int, error) {
	if m.EstimateTokensFunc != nil {
		return m.EstimateTokensFunc(prompt)
	}
	// Simple estimation: 1 token per 4 characters
	return len(prompt) / 4, nil
}

func (m *MockDriver) HealthCheck(ctx context.Context) error {
	if m.HealthCheckFunc != nil {
		return m.HealthCheckFunc(ctx)
	}
	return nil
}

func (m *MockDriver) Configure(config map[string]interface{}) error {
	if m.ConfigureFunc != nil {
		return m.ConfigureFunc(config)
	}
	return nil
}

func TestDriverRegistry(t *testing.T) {
	registry := NewDriverRegistry()

	// Test registering a driver
	registry.Register("test-driver", func() Driver {
		return &MockDriver{}
	})

	// Test getting a registered driver
	driver, err := registry.Get("test-driver")
	if err != nil {
		t.Fatalf("Failed to get registered driver: %v", err)
	}

	if driver == nil {
		t.Error("Expected driver to be non-nil")
	}

	// Test getting a non-existent driver
	_, err = registry.Get("non-existent")
	if err == nil {
		t.Error("Expected error for non-existent driver")
	}

	if _, ok := err.(*DriverNotFoundError); !ok {
		t.Error("Expected DriverNotFoundError")
	}
}

func TestDriverNotFoundError(t *testing.T) {
	err := &DriverNotFoundError{Name: "test-driver"}

	expectedMsg := "driver not found: test-driver"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message '%s', got '%s'", expectedMsg, err.Error())
	}
}

func TestCapabilities(t *testing.T) {
	caps := Capabilities{
		ModelName:               "test-model",
		MaxTokensPerRequest:     100000,
		MaxTokensPerResponse:    4096,
		CostPer1KTokens:         0.003,
		SupportsJSONMode:        true,
		SupportsFunctionCalling: false,
	}

	// Test token budget calculation
	promptTokens := 1000
	responseTokens := 500
	totalTokens := promptTokens + responseTokens
	expectedCost := float64(totalTokens) * caps.CostPer1KTokens / 1000.0

	if expectedCost != 0.0045 {
		t.Errorf("Expected cost to be 0.0045, got %f", expectedCost)
	}

	// Test token limits
	if caps.MaxTokensPerRequest < caps.MaxTokensPerResponse {
		t.Error("MaxTokensPerRequest should be greater than MaxTokensPerResponse")
	}
}

func TestDefaultRegistry(t *testing.T) {
	// Test that DefaultRegistry is initialized
	if DefaultRegistry == nil {
		t.Error("DefaultRegistry should not be nil")
	}

	// Test registering to default registry
	DefaultRegistry.Register("test-default", func() Driver {
		return &MockDriver{}
	})

	driver, err := DefaultRegistry.Get("test-default")
	if err != nil {
		t.Fatalf("Failed to get driver from default registry: %v", err)
	}

	if driver == nil {
		t.Error("Expected driver to be non-nil")
	}
}

func TestMockDriverEnrich(t *testing.T) {
	ctx := context.Background()
	findings := []models.Finding{
		{
			ID:       "test-1",
			Severity: "high",
			Title:    "Test Finding",
		},
	}

	mockDriver := &MockDriver{
		EnrichFunc: func(ctx context.Context, f []models.Finding, prompt string) ([]enrichment.FindingEnrichment, error) {
			return []enrichment.FindingEnrichment{
				{
					FindingID: f[0].ID,
					Analysis: enrichment.Analysis{
						BusinessImpact: "Test enrichment",
					},
				},
			}, nil
		},
	}

	enrichments, err := mockDriver.Enrich(ctx, findings, "test prompt")
	if err != nil {
		t.Fatalf("Enrich failed: %v", err)
	}

	if len(enrichments) != 1 {
		t.Errorf("Expected 1 enrichment, got %d", len(enrichments))
	}

	if enrichments[0].FindingID != "test-1" {
		t.Errorf("Expected finding ID to be 'test-1', got %s", enrichments[0].FindingID)
	}
}
