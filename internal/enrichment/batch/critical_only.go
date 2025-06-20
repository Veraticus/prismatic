package batch

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/joshsymonds/prismatic/internal/models"
)

// CriticalOnlyStrategy only enriches critical severity findings.
type CriticalOnlyStrategy struct{}

// NewCriticalOnlyStrategy creates a new critical-only strategy.
func NewCriticalOnlyStrategy() *CriticalOnlyStrategy {
	return &CriticalOnlyStrategy{}
}

// Name returns the strategy name.
func (s *CriticalOnlyStrategy) Name() string {
	return "critical-only"
}

// Description returns a human-readable description.
func (s *CriticalOnlyStrategy) Description() string {
	return "Only enrich critical severity findings to minimize costs"
}

// Batch implements BatchingStrategy interface.
func (s *CriticalOnlyStrategy) Batch(_ context.Context, findings []models.Finding, config *Config) ([]Batch, error) {
	// Filter for critical findings only
	var criticalFindings []models.Finding
	for _, f := range findings {
		if f.Severity == models.SeverityCritical {
			criticalFindings = append(criticalFindings, f)
		}
	}

	if len(criticalFindings) == 0 {
		return []Batch{}, nil
	}

	// Group critical findings by scanner and resource type
	groups := make(map[string][]models.Finding)
	for _, f := range criticalFindings {
		key := fmt.Sprintf("%s:%s", f.Scanner, f.Type)
		groups[key] = append(groups[key], f)
	}

	// Create batches
	var batches []Batch
	for groupKey, groupFindings := range groups {
		// Split into smaller batches if needed
		for i := 0; i < len(groupFindings); i += config.MaxFindingsPerBatch {
			end := i + config.MaxFindingsPerBatch
			if end > len(groupFindings) {
				end = len(groupFindings)
			}

			batch := Batch{
				ID:              uuid.New().String(),
				Findings:        groupFindings[i:end],
				Strategy:        s.Name(),
				GroupKey:        groupKey,
				EstimatedTokens: s.estimateTokens(groupFindings[i:end]),
				Priority:        100, // Critical findings always have highest priority
				ShouldSummarize: false,
			}
			batches = append(batches, batch)
		}
	}

	return batches, nil
}

// estimateTokens estimates the token count for a batch.
func (s *CriticalOnlyStrategy) estimateTokens(findings []models.Finding) int {
	// Base tokens for prompt structure
	baseTokens := 500

	// Estimate tokens per finding (critical findings may need more detail)
	tokensPerFinding := 250

	return baseTokens + (tokensPerFinding * len(findings))
}

// init registers the strategy.
func init() {
	DefaultRegistry.Register("critical-only", func() BatchingStrategy {
		return NewCriticalOnlyStrategy()
	})
}
