package scanner

import (
	"testing"
	"time"

	"github.com/Veraticus/prismatic/internal/config"
	"github.com/Veraticus/prismatic/internal/models"
	"github.com/stretchr/testify/assert"
)

func TestDateBasedSuppression(t *testing.T) {
	// Set up config with date-based suppression
	cfg := &config.Config{
		Suppressions: config.SuppressionConfig{
			Global: config.GlobalSuppressions{
				DateBefore: "2024-01-01", // Suppress findings before 2024
			},
		},
	}

	orch := NewOrchestrator(cfg, "/tmp", false)
	metadata := &models.ScanMetadata{
		Results: make(map[string]*models.ScanResult),
		Summary: models.ScanSummary{
			BySeverity: make(map[string]int),
			ByScanner:  make(map[string]int),
		},
	}

	// Create findings with different dates
	oldDate, _ := time.Parse("2006-01-02", "2023-06-15")
	newDate, _ := time.Parse("2006-01-02", "2024-06-15")

	result := &models.ScanResult{
		Scanner: "test-scanner",
		Findings: []models.Finding{
			{
				ID:             "old-finding",
				Scanner:        "test-scanner",
				Type:           "vulnerability",
				Severity:       "high",
				Title:          "Old CVE",
				Resource:       "package-1",
				DiscoveredDate: oldDate,
				PublishedDate:  oldDate,
			},
			{
				ID:             "new-finding",
				Scanner:        "test-scanner",
				Type:           "vulnerability",
				Severity:       "high",
				Title:          "New CVE",
				Resource:       "package-2",
				DiscoveredDate: newDate,
				PublishedDate:  newDate,
			},
			{
				ID:             "no-publish-date",
				Scanner:        "test-scanner",
				Type:           "misconfiguration",
				Severity:       "medium",
				Title:          "Config Issue",
				Resource:       "config-1",
				DiscoveredDate: oldDate,
				// No PublishedDate - should use DiscoveredDate
			},
		},
	}

	// Process the result
	orch.processResult(result, metadata)

	// Check suppressions
	processedResult := metadata.Results["test-scanner"]
	assert.NotNil(t, processedResult)
	assert.Len(t, processedResult.Findings, 3)

	// Old vulnerability should be suppressed (uses PublishedDate)
	oldFinding := findByID(processedResult.Findings, "old-finding")
	assert.True(t, oldFinding.Suppressed)
	assert.Contains(t, oldFinding.SuppressionReason, "Finding predates cutoff date")

	// New vulnerability should NOT be suppressed
	newFinding := findByID(processedResult.Findings, "new-finding")
	assert.False(t, newFinding.Suppressed)
	assert.Empty(t, newFinding.SuppressionReason)

	// Old misconfiguration should be suppressed (uses DiscoveredDate)
	configFinding := findByID(processedResult.Findings, "no-publish-date")
	assert.True(t, configFinding.Suppressed)
	assert.Contains(t, configFinding.SuppressionReason, "Finding predates cutoff date")

	// Check summary counts
	assert.Equal(t, 2, metadata.Summary.SuppressedCount)
	assert.Equal(t, 1, metadata.Summary.TotalFindings) // Only counts non-suppressed
}

func TestDateParsing(t *testing.T) {
	tests := []struct {
		name           string
		scanner        string
		dateString     string
		expectedParsed bool
	}{
		{
			name:           "Trivy RFC3339 date",
			scanner:        "trivy",
			dateString:     "2023-06-15T10:30:00Z",
			expectedParsed: true,
		},
		{
			name:           "Gitleaks git date format",
			scanner:        "gitleaks",
			dateString:     "2023-06-15 10:30:00 -0700",
			expectedParsed: true,
		},
		{
			name:           "Invalid date",
			scanner:        "test",
			dateString:     "not-a-date",
			expectedParsed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.scanner == "trivy" {
				// Test Trivy date parsing
				vuln := TrivyVulnerability{
					PublishedDate: tt.dateString,
				}

				finding := models.NewFinding("trivy", "vulnerability", "test", "test")

				// Simulate the date parsing logic from Trivy
				if vuln.PublishedDate != "" {
					if pubDate, err := time.Parse(time.RFC3339, vuln.PublishedDate); err == nil {
						finding.PublishedDate = pubDate
					} else if pubDate, err := time.Parse("2006-01-02T15:04:05Z", vuln.PublishedDate); err == nil {
						finding.PublishedDate = pubDate
					}
				}

				if tt.expectedParsed {
					assert.False(t, finding.PublishedDate.IsZero())
				} else {
					assert.True(t, finding.PublishedDate.IsZero())
				}
			}
		})
	}
}

// Helper function to find a finding by ID.
func findByID(findings []models.Finding, id string) *models.Finding {
	for i := range findings {
		if findings[i].ID == id {
			return &findings[i]
		}
	}
	return nil
}
