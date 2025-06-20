package batch

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/joshsymonds/prismatic/internal/models"
)

// HighImpactStrategy focuses on production environment findings.
type HighImpactStrategy struct{}

// NewHighImpactStrategy creates a new high-impact strategy.
func NewHighImpactStrategy() *HighImpactStrategy {
	return &HighImpactStrategy{}
}

// Name returns the strategy name.
func (s *HighImpactStrategy) Name() string {
	return "high-impact"
}

// Description returns a human-readable description.
func (s *HighImpactStrategy) Description() string {
	return "Focus on high and critical findings in production environments"
}

// Batch implements BatchingStrategy interface.
func (s *HighImpactStrategy) Batch(_ context.Context, findings []models.Finding, config *Config) ([]Batch, error) {
	// Filter for high-impact findings
	var highImpactFindings []models.Finding

	for _, f := range findings {
		// Include critical and high severity
		if f.Severity != models.SeverityCritical && f.Severity != models.SeverityHigh {
			continue
		}

		// Check if it's a production resource or always include critical
		if f.Severity == models.SeverityCritical || s.isProductionResource(f, config.ClientContext) {
			highImpactFindings = append(highImpactFindings, f)
		}
	}

	if len(highImpactFindings) == 0 {
		return []Batch{}, nil
	}

	// Group by scanner and severity
	groups := make(map[string][]models.Finding)
	for _, f := range highImpactFindings {
		key := fmt.Sprintf("%s:%s", f.Scanner, f.Severity)
		groups[key] = append(groups[key], f)
	}

	// Create batches
	var batches []Batch
	for groupKey, groupFindings := range groups {
		// Determine if we should summarize
		shouldSummarize := len(groupFindings) > 15
		summaryReason := ""
		if shouldSummarize {
			summaryReason = fmt.Sprintf("Large group of %d high-impact findings", len(groupFindings))
		}

		// Create batches
		if !shouldSummarize {
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
					ShouldSummarize: false,
				}
				batches = append(batches, batch)
			}
		} else {
			batch := Batch{
				ID:              uuid.New().String(),
				Findings:        groupFindings,
				Strategy:        s.Name(),
				GroupKey:        groupKey,
				EstimatedTokens: s.estimateTokens(groupFindings),
				Priority:        s.calculatePriority(groupFindings),
				ShouldSummarize: true,
				SummaryReason:   summaryReason,
			}
			batches = append(batches, batch)
		}
	}

	return batches, nil
}

// isProductionResource checks if a finding is from a production resource.
func (s *HighImpactStrategy) isProductionResource(finding models.Finding, clientContext map[string]any) bool {
	resource := strings.ToLower(finding.Resource)

	// Check resource name
	productionIndicators := []string{"prod", "production", "prd", "live"}
	for _, indicator := range productionIndicators {
		if strings.Contains(resource, indicator) {
			return true
		}
	}

	// Check client context for production identifiers
	if clientContext != nil {
		// Check for production AWS accounts
		if prodAccounts, ok := clientContext["production_accounts"].([]any); ok {
			for _, account := range prodAccounts {
				if strings.Contains(resource, fmt.Sprintf("%v", account)) {
					return true
				}
			}
		}

		// Check for production namespaces
		if prodNamespaces, ok := clientContext["production_namespaces"].([]any); ok {
			for _, ns := range prodNamespaces {
				if strings.Contains(resource, fmt.Sprintf("%v", ns)) {
					return true
				}
			}
		}
	}

	return false
}

// calculatePriority calculates the priority for a batch.
func (s *HighImpactStrategy) calculatePriority(findings []models.Finding) int {
	if len(findings) == 0 {
		return 0
	}

	// Base priority on severity
	priority := 0
	hasCritical := false

	for _, f := range findings {
		if f.Severity == models.SeverityCritical {
			hasCritical = true
			break
		}
	}

	if hasCritical {
		priority = 100
	} else {
		priority = 75 // All high severity
	}

	return priority
}

// estimateTokens estimates the token count for a batch.
func (s *HighImpactStrategy) estimateTokens(findings []models.Finding) int {
	// Base tokens for prompt structure
	baseTokens := 500

	// Estimate tokens per finding
	tokensPerFinding := 200

	// If summarizing, reduce estimate
	if len(findings) > 15 {
		return baseTokens + (tokensPerFinding * 5)
	}

	return baseTokens + (tokensPerFinding * len(findings))
}

// init registers the strategy.
func init() {
	DefaultRegistry.Register("high-impact", func() BatchingStrategy {
		return NewHighImpactStrategy()
	})
}
