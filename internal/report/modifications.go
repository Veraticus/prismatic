package report

import (
	"fmt"
	"os"
	"time"

	"github.com/Veraticus/prismatic/internal/models"
	"github.com/Veraticus/prismatic/pkg/logger"
	"gopkg.in/yaml.v3"
)

// Modifications represents manual modifications to scan results.
type Modifications struct {
	LastModified time.Time          `yaml:"last_modified"`
	Comments     map[string]string  `yaml:"comments"`
	Version      string             `yaml:"version"`
	Author       string             `yaml:"author"`
	Description  string             `yaml:"description"`
	Suppressions []Suppression      `yaml:"suppressions"`
	Overrides    []SeverityOverride `yaml:"overrides"`
}

// Suppression represents a manual suppression of a finding.
type Suppression struct {
	SuppressedAt time.Time  `yaml:"suppressed_at"`
	ExpiresAt    *time.Time `yaml:"expires_at,omitempty"`
	FindingID    string     `yaml:"finding_id"`
	Reason       string     `yaml:"reason"`
	SuppressedBy string     `yaml:"suppressed_by"`
}

// SeverityOverride represents a manual severity override.
type SeverityOverride struct {
	OverriddenAt time.Time `yaml:"overridden_at"`
	FindingID    string    `yaml:"finding_id"`
	NewSeverity  string    `yaml:"new_severity"`
	Reason       string    `yaml:"reason"`
	OverriddenBy string    `yaml:"overridden_by"`
}

// LoadModifications loads modifications from a YAML file.
func LoadModifications(path string) (*Modifications, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading modifications file: %w", err)
	}

	var mods Modifications
	if err := yaml.Unmarshal(data, &mods); err != nil {
		return nil, fmt.Errorf("parsing modifications YAML: %w", err)
	}

	// Validate version
	if mods.Version != "1.0" {
		return nil, fmt.Errorf("unsupported modifications version: %s", mods.Version)
	}

	// Validate severities
	for _, override := range mods.Overrides {
		if !isValidSeverity(override.NewSeverity) {
			return nil, fmt.Errorf("invalid severity '%s' for finding %s",
				override.NewSeverity, override.FindingID)
		}
	}

	return &mods, nil
}

// ApplyModifications applies manual modifications to findings.
func (m *Modifications) ApplyModifications(findings []models.Finding) []models.Finding {
	// Create maps for efficient lookups
	suppressionMap := make(map[string]Suppression)
	for _, s := range m.Suppressions {
		suppressionMap[s.FindingID] = s
	}

	overrideMap := make(map[string]SeverityOverride)
	for _, o := range m.Overrides {
		overrideMap[o.FindingID] = o
	}

	// Apply modifications
	modified := make([]models.Finding, len(findings))
	modCount := 0

	for i, finding := range findings {
		modified[i] = finding

		// Check for suppression
		if suppression, exists := suppressionMap[finding.ID]; exists {
			// Check if suppression has expired
			if suppression.ExpiresAt != nil && suppression.ExpiresAt.Before(time.Now()) {
				logger.Warn("Suppression expired",
					"finding_id", finding.ID,
					"expired_at", suppression.ExpiresAt)
			} else {
				modified[i].Suppressed = true
				modified[i].SuppressionReason = suppression.Reason
				modCount++
				logger.Debug("Applied suppression",
					"finding_id", finding.ID,
					"reason", suppression.Reason)
			}
		}

		// Check for severity override
		if override, exists := overrideMap[finding.ID]; exists {
			originalSeverity := modified[i].Severity
			modified[i].Severity = override.NewSeverity
			modified[i].OriginalSeverity = originalSeverity
			modCount++
			logger.Debug("Applied severity override",
				"finding_id", finding.ID,
				"original", originalSeverity,
				"new", override.NewSeverity)
		}

		// Add comment if exists
		if comment, exists := m.Comments[finding.ID]; exists {
			modified[i].Comment = comment
		}
	}

	logger.Info("Applied manual modifications",
		"total_findings", len(findings),
		"modifications", modCount)

	return modified
}

// SaveModifications saves modifications to a YAML file.
func SaveModifications(path string, mods *Modifications) error {
	// Update metadata
	mods.LastModified = time.Now()
	if mods.Version == "" {
		mods.Version = "1.0"
	}

	// Marshal to YAML
	data, err := yaml.Marshal(mods)
	if err != nil {
		return fmt.Errorf("marshaling modifications: %w", err)
	}

	// Write to file
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("writing modifications file: %w", err)
	}

	return nil
}

// isValidSeverity checks if a severity value is valid.
func isValidSeverity(severity string) bool {
	validSeverities := []string{"critical", "high", "medium", "low", "info"}
	for _, v := range validSeverities {
		if severity == v {
			return true
		}
	}
	return false
}

// Example creates an example modifications file.
func Example() *Modifications {
	now := time.Now()
	futureExpiry := now.Add(30 * 24 * time.Hour) // 30 days

	return &Modifications{
		Version:      "1.0",
		LastModified: now,
		Author:       "security-team@example.com",
		Description:  "Manual modifications for Q4 2024 security scan",
		Suppressions: []Suppression{
			{
				FindingID:    "abc123def456",
				Reason:       "False positive - this S3 bucket is intentionally public for static website hosting",
				SuppressedBy: "john.doe@example.com",
				SuppressedAt: now,
				ExpiresAt:    &futureExpiry,
			},
			{
				FindingID:    "ghi789jkl012",
				Reason:       "Accepted risk - legacy system scheduled for decommission in Q1 2025",
				SuppressedBy: "jane.smith@example.com",
				SuppressedAt: now,
			},
		},
		Overrides: []SeverityOverride{
			{
				FindingID:    "mno345pqr678",
				NewSeverity:  "low",
				Reason:       "Reduced severity - mitigating controls in place",
				OverriddenBy: "security-team@example.com",
				OverriddenAt: now,
			},
		},
		Comments: map[string]string{
			"stu901vwx234": "Tracking in JIRA ticket SEC-1234",
			"yza567bcd890": "Remediation planned for next sprint",
		},
	}
}
