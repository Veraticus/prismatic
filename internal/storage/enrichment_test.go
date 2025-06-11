package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/joshsymonds/prismatic/internal/models"
)

func TestSaveAndLoadFindingsWithBusinessContext(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "storage-enrichment-test-*")
	require.NoError(t, err)
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	storage := NewStorage(tmpDir)

	// Create test data with findings that have business context
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
						BusinessContext: &models.BusinessContext{
							Owner:              "data-team",
							DataClassification: "confidential",
							BusinessImpact:     "Critical data storage",
							ComplianceImpact:   []string{"SOC2", "GDPR"},
						},
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
						BusinessContext: &models.BusinessContext{
							Owner:              "platform-team",
							DataClassification: "internal",
							BusinessImpact:     "Main API service",
							ComplianceImpact:   []string{"PCI-DSS"},
						},
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
	}

	// Test save
	outputDir := filepath.Join(tmpDir, "scans", metadata.ID)
	err = storage.SaveScanResults(outputDir, metadata)
	require.NoError(t, err)

	// Verify files were created
	assert.FileExists(t, filepath.Join(outputDir, "metadata.json"))
	assert.FileExists(t, filepath.Join(outputDir, "findings.json"))
	// Should NOT create enriched_findings.json anymore
	assert.NoFileExists(t, filepath.Join(outputDir, "enriched_findings.json"))

	// Test load
	loadedMetadata, err := storage.LoadScanResults(outputDir)
	require.NoError(t, err)

	// Verify basic metadata
	assert.Equal(t, metadata.ID, loadedMetadata.ID)
	assert.Equal(t, metadata.ClientName, loadedMetadata.ClientName)
	assert.Equal(t, metadata.Environment, loadedMetadata.Environment)

	// Verify findings with business context were loaded
	prowlerFindings := loadedMetadata.Results["prowler"].Findings
	require.Len(t, prowlerFindings, 1)

	// Check business context was preserved
	finding1 := prowlerFindings[0]
	require.NotNil(t, finding1.BusinessContext)
	assert.Equal(t, "data-team", finding1.BusinessContext.Owner)
	assert.Equal(t, "confidential", finding1.BusinessContext.DataClassification)
	assert.Equal(t, "Critical data storage", finding1.BusinessContext.BusinessImpact)
	assert.ElementsMatch(t, []string{"SOC2", "GDPR"}, finding1.BusinessContext.ComplianceImpact)

	trivyFindings := loadedMetadata.Results["trivy"].Findings
	require.Len(t, trivyFindings, 1)

	finding2 := trivyFindings[0]
	require.NotNil(t, finding2.BusinessContext)
	assert.Equal(t, "platform-team", finding2.BusinessContext.Owner)
	assert.Equal(t, "internal", finding2.BusinessContext.DataClassification)
	assert.Equal(t, "Main API service", finding2.BusinessContext.BusinessImpact)
	assert.ElementsMatch(t, []string{"PCI-DSS"}, finding2.BusinessContext.ComplianceImpact)
}

func TestLoadWithoutBusinessContext(t *testing.T) {
	// Test that loading works even when findings have no business context
	tmpDir, err := os.MkdirTemp("", "storage-no-enrichment-test-*")
	require.NoError(t, err)
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	storage := NewStorage(tmpDir)

	// Create metadata with findings that have no business context
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
						// No BusinessContext
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

	// Save
	outputDir := filepath.Join(tmpDir, "scans", metadata.ID)
	err = storage.SaveScanResults(outputDir, metadata)
	require.NoError(t, err)

	// Load and verify
	loadedMetadata, err := storage.LoadScanResults(outputDir)
	require.NoError(t, err)

	// Should load successfully with nil business context
	finding := loadedMetadata.Results["prowler"].Findings[0]
	assert.Nil(t, finding.BusinessContext)
	assert.Equal(t, metadata.ClientName, loadedMetadata.ClientName)
}

func TestComplexFindingWithAllFields(t *testing.T) {
	// Test with more complex finding data including all optional fields
	tmpDir, err := os.MkdirTemp("", "storage-complex-test-*")
	require.NoError(t, err)
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	storage := NewStorage(tmpDir)

	metadata := &models.ScanMetadata{
		ID:          "complex-scan",
		StartTime:   time.Now(),
		EndTime:     time.Now(),
		ClientName:  "Complex Corp",
		Environment: "Production",
		Results: map[string]*models.ScanResult{
			"nuclei": {
				Scanner: "nuclei",
				Findings: []models.Finding{
					{
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
						BusinessContext: &models.BusinessContext{
							Owner:              "security-team",
							DataClassification: "restricted",
							BusinessImpact:     "Could expose all user data",
							ComplianceImpact:   []string{"GDPR", "CCPA", "SOC2", "ISO27001"},
						},
						RemediationDetails: &models.RemediationDetails{
							Effort:      "medium",
							AutoFixable: false,
							TicketURL:   "https://jira.example.com/SEC-1234",
						},
					},
				},
			},
		},
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
	findings := loadedMetadata.Results["nuclei"].Findings
	require.Len(t, findings, 1)
	f := findings[0]

	// Check all fields
	assert.Equal(t, "finding-1", f.ID)
	assert.Equal(t, "high", f.Severity)
	assert.Equal(t, "critical", f.OriginalSeverity)
	assert.True(t, f.Suppressed)
	assert.Equal(t, "False positive - input is sanitized", f.SuppressionReason)
	assert.Equal(t, "POST", f.Metadata["method"])
	assert.Contains(t, f.References, "CWE-89")

	// Check business context
	require.NotNil(t, f.BusinessContext)
	assert.Equal(t, "security-team", f.BusinessContext.Owner)
	assert.Len(t, f.BusinessContext.ComplianceImpact, 4)

	// Check remediation details
	require.NotNil(t, f.RemediationDetails)
	assert.Equal(t, "medium", f.RemediationDetails.Effort)
	assert.False(t, f.RemediationDetails.AutoFixable)
	assert.Equal(t, "https://jira.example.com/SEC-1234", f.RemediationDetails.TicketURL)
}
