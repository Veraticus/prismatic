package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Veraticus/prismatic/internal/models"
)

func TestSaveAndLoadEnrichedFindings(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "storage-enrichment-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	storage := NewStorage(tmpDir)

	// Create test data with enriched findings
	metadata := &models.ScanMetadata{
		ID:          "test-scan-001",
		StartTime:   time.Now().Add(-10 * time.Minute),
		EndTime:     time.Now(),
		ClientName:  "ACME Corp",
		Environment: "Production",
		ConfigFile:  "test-config.yaml",
		Scanners:    []string{"prowler", "trivy"},
		Results: map[string]*models.ScanResult{
			"prowler": {
				Scanner:   "prowler",
				StartTime: time.Now().Add(-10 * time.Minute),
				EndTime:   time.Now().Add(-5 * time.Minute),
				Findings: []models.Finding{
					{
						ID:       "finding-1",
						Scanner:  "prowler",
						Type:     "aws-misconfiguration",
						Severity: "high",
						Title:    "S3 bucket publicly accessible",
						Resource: "arn:aws:s3:::test-bucket",
					},
				},
			},
			"trivy": {
				Scanner:   "trivy",
				StartTime: time.Now().Add(-5 * time.Minute),
				EndTime:   time.Now(),
				Findings: []models.Finding{
					{
						ID:       "finding-2",
						Scanner:  "trivy",
						Type:     "vulnerability",
						Severity: "critical",
						Title:    "CVE-2024-1234",
						Resource: "api:latest",
					},
				},
			},
		},
		Summary: models.ScanSummary{
			BySeverity: map[string]int{
				"critical": 1,
				"high":     1,
			},
			ByScanner: map[string]int{
				"prowler": 1,
				"trivy":   1,
			},
			TotalFindings: 2,
		},
		EnrichedFindings: []models.EnrichedFinding{
			{
				Finding: models.Finding{
					ID:       "finding-1",
					Scanner:  "prowler",
					Type:     "aws-misconfiguration",
					Severity: "high",
					Title:    "S3 bucket publicly accessible",
					Resource: "arn:aws:s3:::test-bucket",
				},
				BusinessContext: models.BusinessContext{
					Owner:              "data-team",
					DataClassification: "confidential",
					BusinessImpact:     "Critical data storage",
					ComplianceImpact:   []string{"SOC2", "GDPR"},
				},
			},
			{
				Finding: models.Finding{
					ID:       "finding-2",
					Scanner:  "trivy",
					Type:     "vulnerability",
					Severity: "critical",
					Title:    "CVE-2024-1234",
					Resource: "api:latest",
				},
				BusinessContext: models.BusinessContext{
					Owner:              "platform-team",
					DataClassification: "internal",
					BusinessImpact:     "Main API service",
					ComplianceImpact:   []string{"PCI-DSS"},
				},
			},
		},
	}

	// Test save
	outputDir := filepath.Join(tmpDir, "scans", metadata.ID)
	err = storage.SaveScanResults(outputDir, metadata)
	require.NoError(t, err)

	// Verify files were created
	assert.FileExists(t, filepath.Join(outputDir, "metadata.json"))
	assert.FileExists(t, filepath.Join(outputDir, "findings.json"))
	assert.FileExists(t, filepath.Join(outputDir, "enriched_findings.json"))

	// Test load
	loadedMetadata, err := storage.LoadScanResults(outputDir)
	require.NoError(t, err)

	// Verify basic metadata
	assert.Equal(t, metadata.ID, loadedMetadata.ID)
	assert.Equal(t, metadata.ClientName, loadedMetadata.ClientName)
	assert.Equal(t, metadata.Environment, loadedMetadata.Environment)

	// Verify enriched findings were loaded
	assert.Len(t, loadedMetadata.EnrichedFindings, 2)

	// Verify enriched finding details
	for i, ef := range loadedMetadata.EnrichedFindings {
		originalEf := metadata.EnrichedFindings[i]

		// Check finding data
		assert.Equal(t, originalEf.ID, ef.ID)
		assert.Equal(t, originalEf.Scanner, ef.Scanner)
		assert.Equal(t, originalEf.Type, ef.Type)
		assert.Equal(t, originalEf.Severity, ef.Severity)
		assert.Equal(t, originalEf.Title, ef.Title)
		assert.Equal(t, originalEf.Resource, ef.Resource)

		// Check business context
		assert.Equal(t, originalEf.BusinessContext.Owner, ef.BusinessContext.Owner)
		assert.Equal(t, originalEf.BusinessContext.DataClassification, ef.BusinessContext.DataClassification)
		assert.Equal(t, originalEf.BusinessContext.BusinessImpact, ef.BusinessContext.BusinessImpact)
		assert.ElementsMatch(t, originalEf.BusinessContext.ComplianceImpact, ef.BusinessContext.ComplianceImpact)
	}
}

func TestLoadWithoutEnrichedFindings(t *testing.T) {
	// Test that loading works even when there are no enriched findings
	tmpDir, err := os.MkdirTemp("", "storage-no-enrichment-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	storage := NewStorage(tmpDir)

	// Create metadata without enriched findings
	metadata := &models.ScanMetadata{
		ID:          "test-scan-002",
		StartTime:   time.Now().Add(-10 * time.Minute),
		EndTime:     time.Now(),
		ClientName:  "Test Corp",
		Environment: "Staging",
		Results: map[string]*models.ScanResult{
			"prowler": {
				Scanner: "prowler",
				Findings: []models.Finding{
					{
						ID:       "finding-1",
						Scanner:  "prowler",
						Type:     "check-123",
						Severity: "low",
						Title:    "Minor issue",
						Resource: "test-resource",
					},
				},
			},
		},
		Summary: models.ScanSummary{
			BySeverity:    map[string]int{"low": 1},
			ByScanner:     map[string]int{"prowler": 1},
			TotalFindings: 1,
		},
	}

	// Save without enriched findings
	outputDir := filepath.Join(tmpDir, "scans", metadata.ID)
	err = storage.SaveScanResults(outputDir, metadata)
	require.NoError(t, err)

	// Verify enriched_findings.json was NOT created
	assert.NoFileExists(t, filepath.Join(outputDir, "enriched_findings.json"))

	// Load and verify
	loadedMetadata, err := storage.LoadScanResults(outputDir)
	require.NoError(t, err)

	// Should load successfully with empty enriched findings
	assert.Empty(t, loadedMetadata.EnrichedFindings)
	assert.Equal(t, metadata.ClientName, loadedMetadata.ClientName)
}

func TestEnrichmentWithComplexData(t *testing.T) {
	// Test with more complex enrichment data including edge cases
	tmpDir, err := os.MkdirTemp("", "storage-complex-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	storage := NewStorage(tmpDir)

	metadata := &models.ScanMetadata{
		ID:          "complex-scan",
		StartTime:   time.Now(),
		EndTime:     time.Now(),
		ClientName:  "Complex Corp",
		Environment: "Production",
		EnrichedFindings: []models.EnrichedFinding{
			{
				Finding: models.Finding{
					ID:               "finding-1",
					Scanner:          "nuclei",
					Type:             "web-vulnerability",
					Severity:         "high",
					OriginalSeverity: "critical", // Test severity override
					Title:            "SQL Injection",
					Description:      "SQL injection vulnerability found",
					Resource:         "https://api.example.com/users",
					Location:         "/users endpoint",
					Framework:        "OWASP",
					Remediation:      "Use parameterized queries",
					Impact:           "Database compromise possible",
					References:       []string{"CWE-89", "OWASP-A03"},
					Metadata: map[string]string{
						"endpoint": "/users",
						"method":   "POST",
					},
					Suppressed:        true,
					SuppressionReason: "False positive - input is sanitized",
					DiscoveredDate:    time.Now().Add(-24 * time.Hour),
					PublishedDate:     time.Now().Add(-48 * time.Hour),
				},
				BusinessContext: models.BusinessContext{
					Owner:              "security-team",
					DataClassification: "restricted",
					BusinessImpact:     "Could expose all user data",
					ComplianceImpact:   []string{"GDPR", "CCPA", "SOC2", "ISO27001"},
				},
				RemediationDetails: models.RemediationDetails{
					Effort:      "medium",
					AutoFixable: false,
					TicketURL:   "https://jira.example.com/SEC-1234",
				},
			},
		},
		Results: make(map[string]*models.ScanResult),
		Summary: models.ScanSummary{
			BySeverity:      map[string]int{"high": 1},
			ByScanner:       map[string]int{"nuclei": 1},
			TotalFindings:   1,
			SuppressedCount: 1,
		},
	}

	// Save
	outputDir := filepath.Join(tmpDir, "scans", metadata.ID)
	err = storage.SaveScanResults(outputDir, metadata)
	require.NoError(t, err)

	// Load
	loadedMetadata, err := storage.LoadScanResults(outputDir)
	require.NoError(t, err)

	// Verify complex data
	require.Len(t, loadedMetadata.EnrichedFindings, 1)
	ef := loadedMetadata.EnrichedFindings[0]

	// Check all fields
	assert.Equal(t, "finding-1", ef.ID)
	assert.Equal(t, "high", ef.Severity)
	assert.Equal(t, "critical", ef.OriginalSeverity)
	assert.True(t, ef.Suppressed)
	assert.Equal(t, "False positive - input is sanitized", ef.SuppressionReason)
	assert.Equal(t, "POST", ef.Metadata["method"])
	assert.Contains(t, ef.References, "CWE-89")

	// Check business context
	assert.Equal(t, "security-team", ef.BusinessContext.Owner)
	assert.Len(t, ef.BusinessContext.ComplianceImpact, 4)

	// Check remediation details
	assert.Equal(t, "medium", ef.RemediationDetails.Effort)
	assert.False(t, ef.RemediationDetails.AutoFixable)
	assert.Equal(t, "https://jira.example.com/SEC-1234", ef.RemediationDetails.TicketURL)
}
