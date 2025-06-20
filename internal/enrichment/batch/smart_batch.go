package batch

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/joshsymonds/prismatic/internal/models"
)

// SmartBatchStrategy implements intelligent grouping and summarization.
type SmartBatchStrategy struct{}

// NewSmartBatchStrategy creates a new smart batch strategy.
func NewSmartBatchStrategy() *SmartBatchStrategy {
	return &SmartBatchStrategy{}
}

// Name returns the strategy name.
func (s *SmartBatchStrategy) Name() string {
	return "smart-batch"
}

// Description returns a human-readable description.
func (s *SmartBatchStrategy) Description() string {
	return "Intelligent grouping by scanner, resource type, and severity with automatic summarization for large groups"
}

// Batch implements BatchingStrategy interface.
func (s *SmartBatchStrategy) Batch(_ context.Context, findings []models.Finding, config *Config) ([]Batch, error) {
	// Set sensible defaults if not configured
	maxPerBatch := config.MaxFindingsPerBatch
	if maxPerBatch <= 0 {
		maxPerBatch = 50 // Default to 50 findings per batch
	}

	// Group findings by scanner and resource type
	groups := s.groupFindings(findings)

	// Create batches from groups
	var batches []Batch

	for groupKey, groupFindings := range groups {
		// Sort findings by severity for consistent ordering
		sort.Slice(groupFindings, func(i, j int) bool {
			return s.severityPriority(groupFindings[i].Severity) > s.severityPriority(groupFindings[j].Severity)
		})

		// Decide if we should summarize this group
		shouldSummarize, reason := s.shouldSummarize(groupFindings)

		// Split large groups into smaller batches if not summarizing
		if !shouldSummarize && len(groupFindings) > maxPerBatch {
			// Split into smaller batches
			for i := 0; i < len(groupFindings); i += maxPerBatch {
				end := i + maxPerBatch
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
			// Create a single batch for this group
			batch := Batch{
				ID:              uuid.New().String(),
				Findings:        groupFindings,
				Strategy:        s.Name(),
				GroupKey:        groupKey,
				EstimatedTokens: s.estimateTokens(groupFindings),
				Priority:        s.calculatePriority(groupFindings),
				ShouldSummarize: shouldSummarize,
				SummaryReason:   reason,
			}
			batches = append(batches, batch)
		}
	}

	// Sort batches by priority
	sort.Slice(batches, func(i, j int) bool {
		return batches[i].Priority > batches[j].Priority
	})

	return batches, nil
}

// groupFindings groups findings by scanner and resource type.
func (s *SmartBatchStrategy) groupFindings(findings []models.Finding) map[string][]models.Finding {
	groups := make(map[string][]models.Finding)

	for _, finding := range findings {
		// Create group key
		key := fmt.Sprintf("%s:%s:%s", finding.Scanner, finding.Type, finding.Severity)
		groups[key] = append(groups[key], finding)
	}

	return groups
}

// shouldSummarize determines if a group should be summarized.
func (s *SmartBatchStrategy) shouldSummarize(findings []models.Finding) (bool, string) {
	// Summarize if more than 10 similar findings
	if len(findings) > 10 {
		// Check if findings are similar
		if s.areFindingsSimilar(findings) {
			return true, fmt.Sprintf("Group contains %d similar findings", len(findings))
		}
	}

	// Summarize if all findings have the same rule ID
	if len(findings) > 5 && s.haveSameRuleID(findings) {
		return true, "All findings have the same rule ID"
	}

	// Summarize low severity findings in large groups
	if len(findings) > 20 && findings[0].Severity == models.SeverityLow {
		return true, "Large group of low severity findings"
	}

	return false, ""
}

// areFindingsSimilar checks if findings are similar enough to summarize.
func (s *SmartBatchStrategy) areFindingsSimilar(findings []models.Finding) bool {
	if len(findings) == 0 {
		return false
	}

	// Check if all findings have similar titles
	baseTitle := findings[0].Title
	for _, f := range findings[1:] {
		if !strings.Contains(f.Title, baseTitle[:minInt(len(baseTitle)/2, 20)]) {
			return false
		}
	}

	return true
}

// haveSameRuleID checks if all findings have the same rule ID (using Type field).
func (s *SmartBatchStrategy) haveSameRuleID(findings []models.Finding) bool {
	if len(findings) == 0 || findings[0].Type == "" {
		return false
	}

	ruleType := findings[0].Type
	for _, f := range findings[1:] {
		if f.Type != ruleType {
			return false
		}
	}

	return true
}

// estimateTokens estimates the token count for a batch.
func (s *SmartBatchStrategy) estimateTokens(findings []models.Finding) int {
	// Base tokens for prompt structure
	baseTokens := 500

	// Estimate tokens per finding
	tokensPerFinding := 200

	// If summarizing, reduce token estimate
	if len(findings) > 10 {
		return baseTokens + (tokensPerFinding * 5) // Only show examples
	}

	return baseTokens + (tokensPerFinding * len(findings))
}

// calculatePriority calculates the priority for a batch.
func (s *SmartBatchStrategy) calculatePriority(findings []models.Finding) int {
	if len(findings) == 0 {
		return 0
	}

	// Base priority on highest severity in batch
	maxSeverity := 0
	for _, f := range findings {
		severity := s.severityPriority(f.Severity)
		if severity > maxSeverity {
			maxSeverity = severity
		}
	}

	// Boost priority for production resources
	productionBoost := 0
	for _, f := range findings {
		if s.isProductionResource(f) {
			productionBoost = 20
			break
		}
	}

	// Boost priority for exploitable findings
	exploitableBoost := 0
	for _, f := range findings {
		if s.isExploitable(f) {
			exploitableBoost = 10
			break
		}
	}

	return maxSeverity + productionBoost + exploitableBoost
}

// severityPriority returns a numeric priority for severity.
func (s *SmartBatchStrategy) severityPriority(severity string) int {
	switch models.NormalizeSeverity(severity) {
	case models.SeverityCritical:
		return 100
	case models.SeverityHigh:
		return 75
	case models.SeverityMedium:
		return 50
	case models.SeverityLow:
		return 25
	case models.SeverityInfo:
		return 10
	default:
		return 0
	}
}

// isProductionResource checks if a finding is from a production resource.
func (s *SmartBatchStrategy) isProductionResource(finding models.Finding) bool {
	resource := strings.ToLower(finding.Resource)
	return strings.Contains(resource, "prod") ||
		strings.Contains(resource, "production") ||
		strings.Contains(resource, "prd")
}

// isExploitable checks if a finding appears to be exploitable.
func (s *SmartBatchStrategy) isExploitable(finding models.Finding) bool {
	title := strings.ToLower(finding.Title)
	desc := strings.ToLower(finding.Description)

	exploitableKeywords := []string{
		"rce", "remote code execution",
		"sql injection", "sqli",
		"command injection",
		"arbitrary file",
		"authentication bypass",
		"privilege escalation",
		"exposed credentials",
		"default password",
	}

	for _, keyword := range exploitableKeywords {
		if strings.Contains(title, keyword) || strings.Contains(desc, keyword) {
			return true
		}
	}

	return false
}

// minInt returns the minimum of two integers.
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// init registers the strategy.
func init() {
	DefaultRegistry.Register("smart-batch", func() BatchingStrategy {
		return NewSmartBatchStrategy()
	})
}
