// Package batch provides strategies for batching security findings for efficient AI enrichment.
package batch

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/joshsymonds/prismatic/internal/models"
)

// AllStrategy enriches all findings regardless of severity.
type AllStrategy struct{}

// NewAllStrategy creates a new all strategy.
func NewAllStrategy() *AllStrategy {
	return &AllStrategy{}
}

// Name returns the strategy name.
func (s *AllStrategy) Name() string {
	return "all"
}

// Description returns a human-readable description.
func (s *AllStrategy) Description() string {
	return "Enrich all findings (highest cost)"
}

// Batch implements BatchingStrategy interface.
func (s *AllStrategy) Batch(_ context.Context, findings []models.Finding, config *Config) ([]Batch, error) {
	// Group by scanner and severity for better organization
	groups := make(map[string][]models.Finding)

	for _, f := range findings {
		key := fmt.Sprintf("%s:%s", f.Scanner, f.Severity)
		groups[key] = append(groups[key], f)
	}

	// Create batches
	var batches []Batch

	for groupKey, groupFindings := range groups {
		// Create batches respecting max findings per batch
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
				Priority:        s.calculatePriority(groupFindings[i:end]),
				ShouldSummarize: false, // Don't summarize in "all" strategy
			}
			batches = append(batches, batch)
		}
	}

	return batches, nil
}

// calculatePriority calculates the priority for a batch.
func (s *AllStrategy) calculatePriority(findings []models.Finding) int {
	if len(findings) == 0 {
		return 0
	}

	// Priority based on highest severity in batch
	maxPriority := 0

	for _, f := range findings {
		priority := 0
		switch f.Severity {
		case models.SeverityCritical:
			priority = 100
		case models.SeverityHigh:
			priority = 75
		case models.SeverityMedium:
			priority = 50
		case models.SeverityLow:
			priority = 25
		case models.SeverityInfo:
			priority = 10
		}

		if priority > maxPriority {
			maxPriority = priority
		}
	}

	return maxPriority
}

// estimateTokens estimates the token count for a batch.
func (s *AllStrategy) estimateTokens(findings []models.Finding) int {
	// Base tokens for prompt structure
	baseTokens := 500

	// Estimate tokens per finding
	tokensPerFinding := 200

	return baseTokens + (tokensPerFinding * len(findings))
}

// init registers the strategy.
func init() {
	DefaultRegistry.Register("all", func() BatchingStrategy {
		return NewAllStrategy()
	})
}
