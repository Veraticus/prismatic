package batch

import (
	"context"
	"fmt"
	"testing"

	"github.com/joshsymonds/prismatic/internal/models"
)

// MockStrategy implements BatchingStrategy for testing.
type MockStrategy struct {
	BatchFunc       func(ctx context.Context, findings []models.Finding, config *Config) ([]Batch, error)
	NameFunc        func() string
	DescriptionFunc func() string
}

func (m *MockStrategy) Batch(ctx context.Context, findings []models.Finding, config *Config) ([]Batch, error) {
	if m.BatchFunc != nil {
		return m.BatchFunc(ctx, findings, config)
	}
	return []Batch{}, nil
}

func (m *MockStrategy) Name() string {
	if m.NameFunc != nil {
		return m.NameFunc()
	}
	return "mock"
}

func (m *MockStrategy) Description() string {
	if m.DescriptionFunc != nil {
		return m.DescriptionFunc()
	}
	return "Mock batching strategy"
}

func TestStrategyRegistry(t *testing.T) {
	registry := NewStrategyRegistry()

	// Test registering a strategy
	registry.Register("test-strategy", func() BatchingStrategy {
		return &MockStrategy{
			NameFunc: func() string { return "test-strategy" },
		}
	})

	// Test getting a registered strategy
	strategy, err := registry.Get("test-strategy")
	if err != nil {
		t.Fatalf("Failed to get registered strategy: %v", err)
	}

	if strategy == nil {
		t.Error("Expected strategy to be non-nil")
	}

	if strategy.Name() != "test-strategy" {
		t.Errorf("Expected strategy name 'test-strategy', got %s", strategy.Name())
	}

	// Test getting a non-existent strategy
	_, err = registry.Get("non-existent")
	if err == nil {
		t.Error("Expected error for non-existent strategy")
	}

	if _, ok := err.(*StrategyNotFoundError); !ok {
		t.Error("Expected StrategyNotFoundError")
	}
}

func TestStrategyNotFoundError(t *testing.T) {
	err := &StrategyNotFoundError{Name: "test-strategy"}

	expectedMsg := "batching strategy not found: test-strategy"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message '%s', got '%s'", expectedMsg, err.Error())
	}
}

func TestBatchCreation(t *testing.T) {
	findings := []models.Finding{
		{ID: "1", Severity: "high"},
		{ID: "2", Severity: "high"},
		{ID: "3", Severity: "medium"},
	}

	batch := Batch{
		ID:              "batch-1",
		Strategy:        "test",
		GroupKey:        "high-severity",
		SummaryReason:   "Grouped by severity",
		Findings:        findings[:2], // First two findings
		EstimatedTokens: 500,
		Priority:        1,
		ShouldSummarize: false,
	}

	if batch.ID != "batch-1" {
		t.Errorf("Expected batch ID 'batch-1', got %s", batch.ID)
	}

	if len(batch.Findings) != 2 {
		t.Errorf("Expected 2 findings in batch, got %d", len(batch.Findings))
	}

	if batch.Priority != 1 {
		t.Errorf("Expected priority 1, got %d", batch.Priority)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		valid  bool
	}{
		{
			name: "Valid config",
			config: Config{
				ClientContext:       map[string]interface{}{"env": "prod"},
				GroupBy:             []string{"severity", "service"},
				MaxTokensPerBatch:   4096,
				MaxFindingsPerBatch: 50,
			},
			valid: true,
		},
		{
			name:   "Empty config (uses defaults)",
			config: Config{},
			valid:  true,
		},
		{
			name: "Config with zero max tokens",
			config: Config{
				MaxTokensPerBatch: 0, // Should mean unlimited
			},
			valid: true,
		},
		{
			name: "Config with negative values",
			config: Config{
				MaxTokensPerBatch:   -1,
				MaxFindingsPerBatch: -1,
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate config
			isValid := tt.config.MaxTokensPerBatch >= 0 && tt.config.MaxFindingsPerBatch >= 0

			if isValid != tt.valid {
				t.Errorf("Expected config validity to be %v, got %v", tt.valid, isValid)
			}
		})
	}
}

func TestDefaultRegistry(t *testing.T) {
	// Test that DefaultRegistry is initialized
	if DefaultRegistry == nil {
		t.Error("DefaultRegistry should not be nil")
	}

	// Test registering to default registry
	DefaultRegistry.Register("test-default", func() BatchingStrategy {
		return &MockStrategy{
			NameFunc: func() string { return "test-default" },
		}
	})

	strategy, err := DefaultRegistry.Get("test-default")
	if err != nil {
		t.Fatalf("Failed to get strategy from default registry: %v", err)
	}

	if strategy == nil {
		t.Error("Expected strategy to be non-nil")
	}
}

func TestBatchPriorityOrdering(t *testing.T) {
	batches := []Batch{
		{ID: "1", Priority: 3},
		{ID: "2", Priority: 1},
		{ID: "3", Priority: 2},
	}

	// Find highest priority batch
	highestPriority := -1
	highestID := ""
	for _, b := range batches {
		if b.Priority > highestPriority {
			highestPriority = b.Priority
			highestID = b.ID
		}
	}

	if highestID != "1" {
		t.Errorf("Expected batch '1' to have highest priority, got %s", highestID)
	}
}

func TestBatchTokenEstimation(t *testing.T) {
	findings := make([]models.Finding, 100)
	for i := range findings {
		findings[i] = models.Finding{
			ID:          fmt.Sprintf("finding-%d", i),
			Title:       "Test finding with a reasonably long title",
			Description: "This is a test finding description that contains enough text to make token estimation meaningful.",
		}
	}

	batch := Batch{
		Findings:        findings,
		EstimatedTokens: len(findings) * 50, // Rough estimate: 50 tokens per finding
	}

	if batch.EstimatedTokens < 1000 {
		t.Error("Expected estimated tokens to be at least 1000 for 100 findings")
	}

	if batch.EstimatedTokens > 10000 {
		t.Error("Expected estimated tokens to be less than 10000 for 100 findings")
	}
}
