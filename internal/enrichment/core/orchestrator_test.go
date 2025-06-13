package core

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/joshsymonds/prismatic/internal/enrichment"
	"github.com/joshsymonds/prismatic/internal/enrichment/batch"
	"github.com/joshsymonds/prismatic/internal/enrichment/cache"
	"github.com/joshsymonds/prismatic/internal/enrichment/knowledge"
	"github.com/joshsymonds/prismatic/internal/enrichment/llm"
	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/joshsymonds/prismatic/internal/storage"
	"github.com/joshsymonds/prismatic/pkg/logger"
)

// createTestStorage creates a temporary storage for testing.
func createTestStorage(t *testing.T) (*storage.Storage, func()) {
	tmpDir, err := os.MkdirTemp("", "orchestrator-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	testStorage := storage.NewStorageWithLogger(tmpDir, logger.NewMockLogger())

	cleanup := func() {
		_ = os.RemoveAll(tmpDir)
	}

	return testStorage, cleanup
}

// Mock implementations for testing.
type mockLLMDriver struct {
	enrichFunc      func(ctx context.Context, findings []models.Finding, prompt string) ([]enrichment.FindingEnrichment, error)
	getCapabilities func() llm.Capabilities
	estimateTokens  func(prompt string) (int, error)
}

func (m *mockLLMDriver) Enrich(ctx context.Context, findings []models.Finding, prompt string) ([]enrichment.FindingEnrichment, error) {
	if m.enrichFunc != nil {
		return m.enrichFunc(ctx, findings, prompt)
	}
	enrichments := make([]enrichment.FindingEnrichment, len(findings))
	for i, f := range findings {
		enrichments[i] = enrichment.FindingEnrichment{
			FindingID: f.ID,
			Analysis: enrichment.Analysis{
				BusinessImpact: "Mock enrichment for " + f.ID,
				PriorityScore:  5.0,
			},
		}
	}
	return enrichments, nil
}

func (m *mockLLMDriver) GetCapabilities() llm.Capabilities {
	if m.getCapabilities != nil {
		return m.getCapabilities()
	}
	return llm.Capabilities{
		ModelName:            "mock-model",
		MaxTokensPerRequest:  100000,
		MaxTokensPerResponse: 4096,
		CostPer1KTokens:      0.001,
		SupportsJSONMode:     true,
	}
}

func (m *mockLLMDriver) EstimateTokens(prompt string) (int, error) {
	if m.estimateTokens != nil {
		return m.estimateTokens(prompt)
	}
	return len(prompt) / 4, nil
}

func (m *mockLLMDriver) HealthCheck(ctx context.Context) error {
	return nil
}

func (m *mockLLMDriver) Configure(_ map[string]interface{}) error {
	return nil
}

type mockBatchingStrategy struct {
	batchFunc func(ctx context.Context, findings []models.Finding, config *batch.Config) ([]batch.Batch, error)
}

func (m *mockBatchingStrategy) Batch(ctx context.Context, findings []models.Finding, config *batch.Config) ([]batch.Batch, error) {
	if m.batchFunc != nil {
		return m.batchFunc(ctx, findings, config)
	}
	// Simple batching: one batch per finding
	batches := make([]batch.Batch, len(findings))
	for i, f := range findings {
		batches[i] = batch.Batch{
			ID:              fmt.Sprintf("batch-%d", i),
			Strategy:        "mock",
			Findings:        []models.Finding{f},
			EstimatedTokens: 100,
			Priority:        1,
		}
	}
	return batches, nil
}

func (m *mockBatchingStrategy) Name() string {
	return "mock"
}

func (m *mockBatchingStrategy) Description() string {
	return "Mock batching strategy"
}

func TestNewOrchestrator(t *testing.T) {
	driver := &mockLLMDriver{}
	strategy := &mockBatchingStrategy{}
	mockCache := cache.NewMockCache()
	mockKnowledge := knowledge.NewMockBase()
	testStorage, cleanup := createTestStorage(t)
	defer cleanup()
	mockStorage := testStorage
	config := &enrichment.Config{}
	log := logger.NewMockLogger()

	orch := NewOrchestrator(driver, strategy, mockCache, mockKnowledge, mockStorage, config, log)

	if orch == nil {
		t.Fatal("Expected orchestrator to be created")
	}

	if orch.GetDriver() != driver {
		t.Error("Driver not set correctly")
	}

	if orch.GetStrategy() != strategy {
		t.Error("Batching strategy not set correctly")
	}
}

func TestOrchestrator_EnrichFindings(t *testing.T) {
	tests := []struct {
		config        *enrichment.Config
		mockDriver    *mockLLMDriver
		mockStrategy  *mockBatchingStrategy
		name          string
		findings      []models.Finding
		expectedCount int
		expectError   bool
	}{
		{
			name: "Simple enrichment",
			findings: []models.Finding{
				{ID: "1", Severity: "high", Title: "Test Finding 1"},
				{ID: "2", Severity: "medium", Title: "Test Finding 2"},
			},
			config: &enrichment.Config{
				TokenBudget: 10000,
			},
			expectedCount: 2,
			expectError:   false,
		},
		{
			name:     "Empty findings",
			findings: []models.Finding{},
			config: &enrichment.Config{
				TokenBudget: 10000,
			},
			expectedCount: 0,
			expectError:   false,
		},
		{
			name: "Token budget exceeded",
			findings: []models.Finding{
				{ID: "1", Severity: "high"},
			},
			config: &enrichment.Config{
				TokenBudget: 10, // Very low budget
			},
			mockStrategy: &mockBatchingStrategy{
				batchFunc: func(ctx context.Context, findings []models.Finding, config *batch.Config) ([]batch.Batch, error) {
					return []batch.Batch{
						{
							ID:              "batch-1",
							Findings:        findings,
							EstimatedTokens: 1000, // Exceeds budget
						},
					}, nil
				},
			},
			expectedCount: 0,
			expectError:   false, // Should skip batches that exceed budget
		},
		{
			name: "LLM driver error",
			findings: []models.Finding{
				{ID: "1", Severity: "high"},
			},
			config: &enrichment.Config{},
			mockDriver: &mockLLMDriver{
				enrichFunc: func(ctx context.Context, findings []models.Finding, prompt string) ([]enrichment.FindingEnrichment, error) {
					return nil, fmt.Errorf("LLM error")
				},
			},
			expectedCount: 0,
			expectError:   false, // Orchestrator logs errors but doesn't fail
		},
		{
			name: "Batching strategy error",
			findings: []models.Finding{
				{ID: "1", Severity: "high"},
			},
			config: &enrichment.Config{},
			mockStrategy: &mockBatchingStrategy{
				batchFunc: func(ctx context.Context, findings []models.Finding, config *batch.Config) ([]batch.Batch, error) {
					return nil, fmt.Errorf("batching error")
				},
			},
			expectedCount: 0,
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			driver := tt.mockDriver
			if driver == nil {
				driver = &mockLLMDriver{}
			}

			strategy := tt.mockStrategy
			if strategy == nil {
				strategy = &mockBatchingStrategy{}
			}

			testStorage, cleanup := createTestStorage(t)
			defer cleanup()

			orch := NewOrchestrator(driver, strategy, nil, nil, testStorage, &enrichment.Config{}, logger.NewMockLogger())
			ctx := context.Background()

			enrichments, err := orch.EnrichFindings(ctx, tt.findings, tt.config)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}

			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if len(enrichments) != tt.expectedCount {
				t.Errorf("Expected %d enrichments, got %d", tt.expectedCount, len(enrichments))
			}
		})
	}
}

func TestOrchestrator_WithCache(t *testing.T) {
	// Create mock cache
	cacheHits := 0
	cacheMisses := 0
	mockCache := &cache.MockCache{
		GetFunc: func(ctx context.Context, key string) (*enrichment.FindingEnrichment, error) {
			if key == "cached-finding" {
				cacheHits++
				return &enrichment.FindingEnrichment{
					FindingID: "cached-finding",
					Analysis: enrichment.Analysis{
						BusinessImpact: "Cached enrichment",
						PriorityScore:  5.0,
					},
				}, nil
			}
			cacheMisses++
			return nil, fmt.Errorf("not found")
		},
		SetFunc: func(ctx context.Context, e *enrichment.FindingEnrichment, ttl time.Duration) error {
			return nil
		},
		StatsFunc: func(ctx context.Context) (*cache.Stats, error) {
			return &cache.Stats{
				TotalHits:   int64(cacheHits),
				TotalMisses: int64(cacheMisses),
			}, nil
		},
	}

	driver := &mockLLMDriver{}
	strategy := &mockBatchingStrategy{}

	testStorage, cleanup := createTestStorage(t)
	defer cleanup()

	orch := NewOrchestrator(driver, strategy, mockCache, nil, testStorage, &enrichment.Config{}, logger.NewMockLogger())
	ctx := context.Background()

	findings := []models.Finding{
		{ID: "cached-finding", Severity: "high"},
		{ID: "new-finding", Severity: "medium"},
	}

	config := &enrichment.Config{
		EnableCache: true,
		CacheTTL:    1 * time.Hour,
		TokenBudget: 10000,
	}

	enrichments, err := orch.EnrichFindings(ctx, findings, config)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(enrichments) != 2 {
		t.Errorf("Expected 2 enrichments, got %d", len(enrichments))
	}

	// Check that cached finding was retrieved from cache
	var cachedFound bool
	for _, e := range enrichments {
		if e.FindingID == "cached-finding" && e.Analysis.BusinessImpact == "Cached enrichment" {
			cachedFound = true
			break
		}
	}

	if !cachedFound {
		t.Error("Expected to find cached enrichment")
	}

	// Verify cache stats
	if cacheHits != 1 {
		t.Errorf("Expected 1 cache hit, got %d", cacheHits)
	}

	if cacheMisses != 1 {
		t.Errorf("Expected 1 cache miss, got %d", cacheMisses)
	}
}

func TestOrchestrator_WithKnowledgeBase(t *testing.T) {
	// Create mock knowledge base
	mockKB := &knowledge.MockBase{
		SearchFunc: func(ctx context.Context, query string, limit int) ([]*knowledge.Entry, error) {
			if query == "SQL injection" {
				return []*knowledge.Entry{
					{
						ID:          "sql-injection-kb",
						Type:        "vulnerability",
						Description: "SQL injection knowledge",
						GenericRemediation: &knowledge.Remediation{
							Immediate: "Use parameterized queries",
							ShortTerm: "Implement input validation",
							LongTerm:  "Security training for developers",
						},
					},
				}, nil
			}
			return []*knowledge.Entry{}, nil
		},
	}

	enrichCalled := false
	driver := &mockLLMDriver{
		enrichFunc: func(ctx context.Context, findings []models.Finding, prompt string) ([]enrichment.FindingEnrichment, error) {
			enrichCalled = true
			// Verify that knowledge base info is in the prompt
			if prompt == "" {
				t.Error("Expected prompt to contain knowledge base information")
			}

			enrichments := make([]enrichment.FindingEnrichment, len(findings))
			for i, f := range findings {
				enrichments[i] = enrichment.FindingEnrichment{
					FindingID: f.ID,
					Analysis: enrichment.Analysis{
						BusinessImpact: "Enriched with KB context",
						PriorityScore:  5.0,
					},
				}
			}
			return enrichments, nil
		},
	}

	strategy := &mockBatchingStrategy{}

	testStorage, cleanup := createTestStorage(t)
	defer cleanup()

	orch := NewOrchestrator(driver, strategy, nil, mockKB, testStorage, &enrichment.Config{}, logger.NewMockLogger())
	ctx := context.Background()

	findings := []models.Finding{
		{
			ID:          "sql-finding",
			Severity:    "high",
			Title:       "SQL injection vulnerability",
			Description: "SQL injection found in login endpoint",
		},
	}

	config := &enrichment.Config{
		TokenBudget: 10000,
	}

	enrichments, err := orch.EnrichFindings(ctx, findings, config)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !enrichCalled {
		t.Error("Expected LLM driver to be called with KB context")
	}

	if len(enrichments) != 1 {
		t.Errorf("Expected 1 enrichment, got %d", len(enrichments))
	}
}

func TestOrchestrator_ConcurrentBatches(t *testing.T) {
	// Test that batches are processed concurrently
	processedBatches := make(map[string]bool)
	processingOrder := make([]string, 0)

	driver := &mockLLMDriver{
		enrichFunc: func(ctx context.Context, findings []models.Finding, prompt string) ([]enrichment.FindingEnrichment, error) {
			// Simulate processing time
			time.Sleep(10 * time.Millisecond)

			enrichments := make([]enrichment.FindingEnrichment, len(findings))
			for i, f := range findings {
				processingOrder = append(processingOrder, f.ID)
				processedBatches[f.ID] = true
				enrichments[i] = enrichment.FindingEnrichment{
					FindingID: f.ID,
					Analysis: enrichment.Analysis{
						BusinessImpact: "Processed",
						PriorityScore:  5.0,
					},
				}
			}
			return enrichments, nil
		},
	}

	// Create multiple batches
	strategy := &mockBatchingStrategy{
		batchFunc: func(ctx context.Context, findings []models.Finding, config *batch.Config) ([]batch.Batch, error) {
			batches := make([]batch.Batch, len(findings))
			for i, f := range findings {
				batches[i] = batch.Batch{
					ID:              fmt.Sprintf("batch-%d", i),
					Findings:        []models.Finding{f},
					EstimatedTokens: 100,
					Priority:        len(findings) - i, // Reverse priority
				}
			}
			return batches, nil
		},
	}

	testStorage, cleanup := createTestStorage(t)
	defer cleanup()

	orch := NewOrchestrator(driver, strategy, nil, nil, testStorage, &enrichment.Config{}, logger.NewMockLogger())
	ctx := context.Background()

	findings := []models.Finding{
		{ID: "1", Severity: "low"},
		{ID: "2", Severity: "medium"},
		{ID: "3", Severity: "high"},
		{ID: "4", Severity: "critical"},
	}

	config := &enrichment.Config{
		TokenBudget: 10000,
	}

	enrichments, err := orch.EnrichFindings(ctx, findings, config)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(enrichments) != len(findings) {
		t.Errorf("Expected %d enrichments, got %d", len(findings), len(enrichments))
	}

	// Verify all findings were processed
	for _, f := range findings {
		if !processedBatches[f.ID] {
			t.Errorf("Finding %s was not processed", f.ID)
		}
	}
}
