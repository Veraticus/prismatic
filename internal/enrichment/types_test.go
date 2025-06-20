package enrichment

import (
	"reflect"
	"testing"
	"time"
)

func TestFindingEnrichmentCreation(t *testing.T) {
	now := time.Now()

	enrichment := FindingEnrichment{
		FindingID: "test-finding-123",
		Analysis: Analysis{
			BusinessImpact:    "High impact on production systems",
			PriorityReasoning: "Critical vulnerability with active exploits",
			TechnicalDetails:  "SQL injection in login endpoint",
			ContextualNotes:   "This service handles authentication",
			RelatedFindings:   []string{"finding-124", "finding-125"},
			PriorityScore:     0.95,
		},
		Remediation: Remediation{
			Immediate:          []string{"Apply WAF rules", "Monitor for exploitation"},
			ShortTerm:          []string{"Fix SQL injection", "Add input validation"},
			LongTerm:           []string{"Implement prepared statements", "Security training"},
			EstimatedEffort:    "2 hours",
			AutomationPossible: true,
			ValidationSteps:    []string{"Run security tests", "Verify fix in staging"},
		},
		Context: map[string]any{
			"environment": "production",
			"service":     "auth-api",
		},
		LLMModel:   "claude-3-sonnet",
		TokensUsed: 300,
		EnrichedAt: now,
	}

	if enrichment.FindingID != "test-finding-123" {
		t.Errorf("Expected FindingID to be 'test-finding-123', got %s", enrichment.FindingID)
	}

	if enrichment.Analysis.PriorityScore != 0.95 {
		t.Errorf("Expected priority score to be 0.95, got %f", enrichment.Analysis.PriorityScore)
	}

	if len(enrichment.Remediation.Immediate) != 2 {
		t.Errorf("Expected 2 immediate remediation steps, got %d", len(enrichment.Remediation.Immediate))
	}

	if enrichment.TokensUsed != 300 {
		t.Errorf("Expected tokens used to be 300, got %d", enrichment.TokensUsed)
	}

	if enrichment.LLMModel != "claude-3-sonnet" {
		t.Errorf("Expected LLM model to be 'claude-3-sonnet', got %s", enrichment.LLMModel)
	}

	if len(enrichment.Context) != 2 {
		t.Errorf("Expected 2 context entries, got %d", len(enrichment.Context))
	}

	if enrichment.Context["environment"] != "production" {
		t.Errorf("Expected environment to be 'production', got %v", enrichment.Context["environment"])
	}

	if !enrichment.EnrichedAt.Equal(now) {
		t.Errorf("Expected EnrichedAt to be %v, got %v", now, enrichment.EnrichedAt)
	}
}

func TestAnalysisValidation(t *testing.T) {
	tests := []struct {
		name     string
		analysis Analysis
		valid    bool
	}{
		{
			name: "Valid analysis",
			analysis: Analysis{
				BusinessImpact:    "High impact on revenue",
				PriorityReasoning: "Critical production issue",
				TechnicalDetails:  "Memory leak causing OOM",
				PriorityScore:     0.8,
			},
			valid: true,
		},
		{
			name: "Invalid priority score (too high)",
			analysis: Analysis{
				BusinessImpact:    "Impact",
				PriorityReasoning: "Reasoning",
				TechnicalDetails:  "Details",
				PriorityScore:     1.5,
			},
			valid: false,
		},
		{
			name: "Invalid priority score (negative)",
			analysis: Analysis{
				BusinessImpact:    "Impact",
				PriorityReasoning: "Reasoning",
				TechnicalDetails:  "Details",
				PriorityScore:     -0.1,
			},
			valid: false,
		},
		{
			name:     "Empty analysis",
			analysis: Analysis{},
			valid:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate priority score is between 0 and 1
			switch {
			case tt.analysis.PriorityScore < 0 || tt.analysis.PriorityScore > 1:
				if tt.valid {
					t.Error("Expected analysis to be valid but priority score is out of range")
				}
			case tt.analysis.BusinessImpact == "" || tt.analysis.PriorityReasoning == "" || tt.analysis.TechnicalDetails == "":
				if tt.valid {
					t.Error("Expected analysis to be valid but has empty fields")
				}
			default:
				if !tt.valid {
					t.Error("Expected analysis to be invalid but it appears valid")
				}
			}
		})
	}
}

func TestRemediationArrays(t *testing.T) {
	remediation := Remediation{
		Immediate: []string{
			"Isolate affected system",
			"Apply emergency patch",
		},
		ShortTerm: []string{
			"Review security policies",
			"Update all dependencies",
			"Conduct security audit",
		},
		LongTerm: []string{
			"Implement security training",
			"Deploy automated scanning",
		},
		ValidationSteps: []string{
			"Run security tests",
			"Verify in staging",
			"Monitor for 24 hours",
		},
		EstimatedEffort:    "1-2 weeks",
		AutomationPossible: true,
	}

	if len(remediation.Immediate) != 2 {
		t.Errorf("Expected 2 immediate steps, got %d", len(remediation.Immediate))
	}

	if len(remediation.ShortTerm) != 3 {
		t.Errorf("Expected 3 short-term steps, got %d", len(remediation.ShortTerm))
	}

	if len(remediation.LongTerm) != 2 {
		t.Errorf("Expected 2 long-term steps, got %d", len(remediation.LongTerm))
	}

	if len(remediation.ValidationSteps) != 3 {
		t.Errorf("Expected 3 validation steps, got %d", len(remediation.ValidationSteps))
	}

	if !remediation.AutomationPossible {
		t.Error("Expected automation to be possible")
	}

	if remediation.EstimatedEffort != "1-2 weeks" {
		t.Errorf("Expected estimated effort '1-2 weeks', got %s", remediation.EstimatedEffort)
	}
}

func TestEnrichmentMetadataCalculations(t *testing.T) {
	startTime := time.Now()
	endTime := startTime.Add(5 * time.Minute)

	metadata := Metadata{
		StartedAt:        startTime,
		CompletedAt:      endTime,
		RunID:            "run-123",
		Strategy:         "smart-batch",
		Driver:           "claude-cli",
		LLMModel:         "claude-3-sonnet",
		TotalFindings:    100,
		EnrichedFindings: 95,
		TotalTokensUsed:  15000,
		Errors:           []string{},
	}

	// Test duration calculation
	duration := metadata.CompletedAt.Sub(metadata.StartedAt)
	if duration != 5*time.Minute {
		t.Errorf("Expected duration to be 5 minutes, got %v", duration)
	}

	// Test enrichment rate
	enrichmentRate := float64(metadata.EnrichedFindings) / float64(metadata.TotalFindings)
	expectedRate := 0.95
	if enrichmentRate != expectedRate {
		t.Errorf("Expected enrichment rate to be %f, got %f", expectedRate, enrichmentRate)
	}

	// Test tokens per finding
	tokensPerFinding := metadata.TotalTokensUsed / metadata.EnrichedFindings
	if tokensPerFinding != 157 { // 15000 / 95 ≈ 157
		t.Errorf("Expected ~157 tokens per finding, got %d", tokensPerFinding)
	}

	// Test other metadata fields
	if metadata.RunID != "run-123" {
		t.Errorf("Expected RunID 'run-123', got %s", metadata.RunID)
	}

	if metadata.Strategy != "smart-batch" {
		t.Errorf("Expected Strategy 'smart-batch', got %s", metadata.Strategy)
	}

	if metadata.Driver != "claude-cli" {
		t.Errorf("Expected Driver 'claude-cli', got %s", metadata.Driver)
	}

	if metadata.LLMModel != "claude-3-sonnet" {
		t.Errorf("Expected LLMModel 'claude-3-sonnet', got %s", metadata.LLMModel)
	}

	if len(metadata.Errors) != 0 {
		t.Errorf("Expected no errors, got %d", len(metadata.Errors))
	}
}

func TestContextMerge(t *testing.T) {
	enrichment := FindingEnrichment{
		Context: map[string]any{
			"key1": "value1",
			"key2": 42,
		},
	}

	// Test merging context
	newContext := map[string]any{
		"key2": 100,      // Override
		"key3": "value3", // New
	}

	for k, v := range newContext {
		enrichment.Context[k] = v
	}

	if enrichment.FindingID != "" {
		t.Error("FindingID should not be set for this test")
	}

	if enrichment.Context["key1"] != "value1" {
		t.Error("Expected key1 to remain unchanged")
	}

	if enrichment.Context["key2"] != 100 {
		t.Error("Expected key2 to be overridden to 100")
	}

	if enrichment.Context["key3"] != "value3" {
		t.Error("Expected key3 to be added")
	}
}

func TestEnrichmentEquality(t *testing.T) {
	e1 := FindingEnrichment{
		FindingID: "test-123",
		Analysis: Analysis{
			BusinessImpact: "Test impact",
		},
		LLMModel: "claude-3-sonnet",
	}

	e2 := FindingEnrichment{
		FindingID: "test-123",
		Analysis: Analysis{
			BusinessImpact: "Test impact",
		},
		LLMModel: "claude-3-sonnet",
	}

	e3 := FindingEnrichment{
		FindingID: "test-456",
		Analysis: Analysis{
			BusinessImpact: "Test impact",
		},
		LLMModel: "claude-3-sonnet",
	}

	if !reflect.DeepEqual(e1, e2) {
		t.Error("Expected e1 and e2 to be equal")
	}

	if reflect.DeepEqual(e1, e3) {
		t.Error("Expected e1 and e3 to be different")
	}
}
