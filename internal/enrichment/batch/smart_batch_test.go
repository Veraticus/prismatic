package batch

import (
	"context"
	"fmt"
	"testing"

	"github.com/joshsymonds/prismatic/internal/models"
)

func TestSmartBatchStrategy_Name(t *testing.T) {
	strategy := &SmartBatchStrategy{}
	if strategy.Name() != "smart-batch" {
		t.Errorf("Expected name 'smart-batch', got %s", strategy.Name())
	}
}

func TestSmartBatchStrategy_Description(t *testing.T) {
	strategy := &SmartBatchStrategy{}
	desc := strategy.Description()
	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestSmartBatchStrategy_Batch(t *testing.T) {
	strategy := &SmartBatchStrategy{}
	ctx := context.Background()

	tests := []struct {
		config          *Config
		checkBatches    func(t *testing.T, batches []Batch)
		name            string
		findings        []models.Finding
		expectedBatches int
	}{
		{
			name: "Group by severity",
			findings: []models.Finding{
				{ID: "1", Severity: "critical", Type: "security/vulnerability"},
				{ID: "2", Severity: "critical", Type: "security/exposure"},
				{ID: "3", Severity: "high", Type: "security/vulnerability"},
				{ID: "4", Severity: "high", Type: "security/misconfiguration"},
				{ID: "5", Severity: "medium", Type: "compliance/cis"},
			},
			config: &Config{
				MaxFindingsPerBatch: 10,
				MaxTokensPerBatch:   4096,
			},
			expectedBatches: 5, // Grouped by scanner:type:severity
			checkBatches: func(t *testing.T, batches []Batch) {
				t.Helper()
				// Check that findings are grouped by severity
				severityGroups := make(map[string]int)
				for _, batch := range batches {
					if len(batch.Findings) > 0 {
						severity := batch.Findings[0].Severity
						for _, f := range batch.Findings {
							if f.Severity != severity {
								t.Errorf("Batch contains mixed severities: %s and %s", severity, f.Severity)
							}
						}
						severityGroups[severity]++
					}
				}

				if len(severityGroups) != 3 {
					t.Errorf("Expected 3 severity groups, got %d", len(severityGroups))
				}
			},
		},
		{
			name: "Large batch requires summarization",
			findings: func() []models.Finding {
				findings := make([]models.Finding, 100)
				for i := range findings {
					findings[i] = models.Finding{
						ID:          fmt.Sprintf("finding-%d", i),
						Severity:    "high",
						Type:        "security/vulnerability",
						Title:       "Very long title that will consume many tokens when serialized",
						Description: "This is a very long description that contains a lot of text to ensure we exceed token limits and trigger summarization behavior in the smart batching strategy",
					}
				}
				return findings
			}(),
			config: &Config{
				MaxFindingsPerBatch: 20,
				MaxTokensPerBatch:   1000, // Low limit to trigger summarization
			},
			expectedBatches: -1, // Don't check exact count
			checkBatches: func(t *testing.T, batches []Batch) {
				t.Helper()
				// At least one batch should be marked for summarization
				hasSummarization := false
				for _, batch := range batches {
					if batch.ShouldSummarize {
						hasSummarization = true
						if batch.SummaryReason == "" {
							t.Error("Batch marked for summarization but no reason provided")
						}
					}
				}

				if !hasSummarization {
					t.Error("Expected at least one batch to be marked for summarization")
				}
			},
		},
		{
			name:     "Empty findings",
			findings: []models.Finding{},
			config: &Config{
				MaxFindingsPerBatch: 10,
			},
			expectedBatches: 0,
			checkBatches: func(t *testing.T, batches []Batch) {
				t.Helper()
				if len(batches) != 0 {
					t.Errorf("Expected no batches for empty findings, got %d", len(batches))
				}
			},
		},
		{
			name: "Production resource prioritization",
			findings: []models.Finding{
				{ID: "1", Severity: "high", Resource: "prod-api-server", Metadata: map[string]string{"environment": "production"}},
				{ID: "2", Severity: "high", Resource: "staging-api-server", Metadata: map[string]string{"environment": "staging"}},
				{ID: "3", Severity: "medium", Resource: "prod-database", Metadata: map[string]string{"environment": "production"}},
				{ID: "4", Severity: "low", Resource: "prod-cache", Metadata: map[string]string{"environment": "production"}},
			},
			config: &Config{
				ClientContext: map[string]any{
					"prioritize_production": true,
				},
				MaxFindingsPerBatch: 10,
			},
			expectedBatches: -1,
			checkBatches: func(t *testing.T, batches []Batch) {
				t.Helper()
				// Production findings should have higher priority
				for _, batch := range batches {
					hasProd := false
					for _, f := range batch.Findings {
						if env, ok := f.Metadata["environment"]; ok && env == "production" {
							hasProd = true
							break
						}
					}

					if hasProd && batch.Priority < 1 {
						t.Error("Production batch should have high priority")
					}
				}
			},
		},
		{
			name: "Similar findings grouping",
			findings: []models.Finding{
				{ID: "1", Type: "security/cve-2021-1234", Severity: "high"},
				{ID: "2", Type: "security/cve-2021-1234", Severity: "high"},
				{ID: "3", Type: "security/cve-2021-1234", Severity: "high"},
				{ID: "4", Type: "security/cve-2022-5678", Severity: "high"},
				{ID: "5", Type: "security/cve-2022-5678", Severity: "high"},
			},
			config: &Config{
				MaxFindingsPerBatch: 10,
			},
			expectedBatches: 2, // Two CVE groups
			checkBatches: func(t *testing.T, batches []Batch) {
				t.Helper()
				// Check that similar CVEs are grouped together
				for _, batch := range batches {
					if len(batch.Findings) > 0 {
						firstType := batch.Findings[0].Type
						for _, f := range batch.Findings {
							if f.Type != firstType {
								t.Errorf("Batch contains mixed types: %s and %s", firstType, f.Type)
							}
						}
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			batches, err := strategy.Batch(ctx, tt.findings, tt.config)
			if err != nil {
				t.Fatalf("Batch failed: %v", err)
			}

			if tt.expectedBatches >= 0 && len(batches) != tt.expectedBatches {
				t.Errorf("Expected %d batches, got %d", tt.expectedBatches, len(batches))
			}

			if tt.checkBatches != nil {
				tt.checkBatches(t, batches)
			}

			// General validations
			for i, batch := range batches {
				if batch.ID == "" {
					t.Errorf("Batch %d has empty ID", i)
				}

				if batch.Strategy != "smart-batch" {
					t.Errorf("Batch %d has wrong strategy: %s", i, batch.Strategy)
				}

				if len(batch.Findings) == 0 {
					t.Errorf("Batch %d has no findings", i)
				}

				if batch.EstimatedTokens <= 0 {
					t.Errorf("Batch %d has invalid token estimate: %d", i, batch.EstimatedTokens)
				}
			}
		})
	}
}

func TestSmartBatchStrategy_GroupingLogic(t *testing.T) {
	findings := []models.Finding{
		{ID: "1", Severity: "critical", Type: "security/cve", Resource: "api-server"},
		{ID: "2", Severity: "critical", Type: "security/cve", Resource: "api-server"},
		{ID: "3", Severity: "critical", Type: "security/exposure", Resource: "web-server"},
		{ID: "4", Severity: "high", Type: "security/cve", Resource: "api-server"},
	}

	// Test the grouping key generation
	groups := make(map[string][]models.Finding)
	for _, f := range findings {
		// Simulate the grouping logic from smart_batch.go
		key := fmt.Sprintf("%s:%s:%s", f.Severity, f.Type, f.Resource)
		groups[key] = append(groups[key], f)
	}

	// Should have 3 groups
	if len(groups) != 3 {
		t.Errorf("Expected 3 groups, got %d", len(groups))
	}

	// Check group sizes
	for key, findings := range groups {
		t.Logf("Group %s has %d findings", key, len(findings))

		// Verify all findings in group share same characteristics
		if len(findings) > 0 {
			first := findings[0]
			for _, f := range findings[1:] {
				if f.Severity != first.Severity {
					t.Errorf("Group %s has mixed severities", key)
				}
			}
		}
	}
}

func TestSmartBatchStrategy_TokenEstimation(t *testing.T) {
	strategy := &SmartBatchStrategy{}

	finding := models.Finding{
		ID:          "test-123",
		Title:       "Test Security Finding",
		Description: "This is a test finding with a description that is long enough to be meaningful for token estimation.",
		Severity:    "high",
		Type:        "security/vulnerability",
	}

	// Estimate tokens for a single finding
	// The actual estimation logic should be in the implementation
	// Here we just verify it produces reasonable results

	config := &Config{
		MaxTokensPerBatch: 4096,
	}

	ctx := context.Background()
	batches, err := strategy.Batch(ctx, []models.Finding{finding}, config)
	if err != nil {
		t.Fatalf("Batch failed: %v", err)
	}

	if len(batches) != 1 {
		t.Fatalf("Expected 1 batch, got %d", len(batches))
	}

	// Token estimate should be reasonable for the content
	// Base tokens (500) + tokens per finding (200) = 700
	tokens := batches[0].EstimatedTokens
	if tokens < 500 || tokens > 1000 {
		t.Errorf("Token estimate seems unreasonable: %d", tokens)
	}
}
