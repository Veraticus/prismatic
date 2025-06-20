package report

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/joshsymonds/prismatic/internal/database"
	"github.com/joshsymonds/prismatic/internal/enrichment"
	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/joshsymonds/prismatic/internal/storage"
	"github.com/joshsymonds/prismatic/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateEnrichmentReport(t *testing.T) {
	// Create in-memory database
	db, err := database.New(":memory:")
	require.NoError(t, err)
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Logf("failed to close database: %v", closeErr)
		}
	}()

	ctx := context.Background()
	scanID, err := db.CreateScan(ctx, &database.Scan{
		Status:    database.ScanStatusCompleted,
		StartedAt: time.Now().Add(-30 * time.Minute),
	})
	require.NoError(t, err)

	// Create metadata with findings
	metadata := &models.ScanMetadata{
		ClientName:  "test-client",
		Environment: "production",
		StartTime:   time.Now().Add(-30 * time.Minute),
		EndTime:     time.Now().Add(-5 * time.Minute),
		Results: map[string]*models.ScanResult{
			"prowler": {
				Scanner: "prowler",
				Findings: []models.Finding{
					{
						ID:          "FINDING-001",
						Scanner:     "prowler",
						Severity:    "critical",
						Title:       "S3 bucket public access",
						Description: "S3 bucket allows public read access",
						Resource:    "arn:aws:s3:::sensitive-data-bucket",
						Type:        "aws-s3",
					},
				},
			},
			"trivy": {
				Scanner: "trivy",
				Findings: []models.Finding{
					{
						ID:          "FINDING-002",
						Scanner:     "trivy",
						Severity:    "high",
						Title:       "Critical vulnerability in nginx",
						Description: "nginx version has known security vulnerabilities",
						Resource:    "nginx:1.14",
						Type:        "vulnerability",
					},
				},
			},
		},
		Summary: models.ScanSummary{
			ByScanner: map[string]int{
				"prowler": 1,
				"trivy":   1,
			},
			TotalFindings: 2,
		},
	}

	// Save the scan data
	store := storage.NewStorage(db)
	err = store.SaveScanResults(scanID, metadata)
	require.NoError(t, err)

	// Save findings to database
	saveFindingsToDatabase(t, db, scanID, metadata)

	// Generate HTML report
	scanIDStr := fmt.Sprintf("%d", scanID)
	generator, err := NewHTMLGeneratorWithDatabase(scanIDStr, db, logger.GetGlobalLogger())
	require.NoError(t, err)

	// Create temp file for output
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.html")

	err = generator.Generate(outputPath)
	require.NoError(t, err)

	// Read and verify the report content
	content, err := os.ReadFile(outputPath) // #nosec G304 - test file path
	require.NoError(t, err)
	html := string(content)

	assert.Contains(t, html, "test-client")
	assert.Contains(t, html, "production")
	assert.Contains(t, html, "S3 bucket public access")
	assert.Contains(t, html, "Critical vulnerability in nginx")
	assert.Contains(t, html, "Total Findings")
	assert.Contains(t, html, "2") // Total findings count
}

func TestGenerateEnrichmentReportWithAIEnrichments(t *testing.T) {
	// Create in-memory database
	db, err := database.New(":memory:")
	require.NoError(t, err)
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Logf("failed to close database: %v", closeErr)
		}
	}()

	ctx := context.Background()
	scanID, err := db.CreateScan(ctx, &database.Scan{
		Status:    database.ScanStatusCompleted,
		StartedAt: time.Now().Add(-30 * time.Minute),
	})
	require.NoError(t, err)

	// Create metadata with findings
	metadata := &models.ScanMetadata{
		ClientName:  "test-client",
		Environment: "production",
		StartTime:   time.Now().Add(-30 * time.Minute),
		EndTime:     time.Now().Add(-5 * time.Minute),
		Results: map[string]*models.ScanResult{
			"prowler": {
				Scanner: "prowler",
				Findings: []models.Finding{
					{
						ID:          "FINDING-001",
						Scanner:     "prowler",
						Severity:    "critical",
						Title:       "S3 bucket public access",
						Description: "S3 bucket allows public read access",
						Resource:    "arn:aws:s3:::customer-data-bucket",
						Type:        "aws-s3",
					},
				},
			},
		},
		Summary: models.ScanSummary{
			ByScanner: map[string]int{
				"prowler": 1,
			},
			TotalFindings: 1,
		},
	}

	// Save the scan data
	store := storage.NewStorage(db)
	err = store.SaveScanResults(scanID, metadata)
	require.NoError(t, err)

	// Save findings to database
	saveFindingsToDatabase(t, db, scanID, metadata)

	// Add AI enrichments
	enrichments := []enrichment.FindingEnrichment{
		{
			FindingID:  "FINDING-001",
			EnrichedAt: time.Now(),
			Analysis: enrichment.Analysis{
				BusinessImpact:    "Exposed customer PII data could lead to GDPR violations and fines up to 4% of annual revenue",
				PriorityScore:     0.95,
				PriorityReasoning: "Production bucket containing customer data with public access is a critical security issue",
				TechnicalDetails:  "Bucket policy allows s3:GetObject from principal '*' without conditions",
				ContextualNotes:   "This bucket stores daily customer data exports and transaction logs",
			},
			Remediation: enrichment.Remediation{
				EstimatedEffort: "30 minutes",
				Immediate: []string{
					"Block all public access on the S3 bucket immediately",
					"Enable S3 bucket logging to audit any access attempts",
				},
				ShortTerm: []string{
					"Implement bucket policies restricting access to specific IAM roles",
					"Enable S3 encryption at rest",
				},
				LongTerm: []string{
					"Migrate sensitive data to a dedicated VPC with S3 VPC endpoints",
					"Implement data classification and automated access controls",
				},
			},
		},
	}

	err = store.SaveEnrichments(scanID, enrichments, &enrichment.Metadata{
		StartedAt:        time.Now().Add(-5 * time.Minute),
		CompletedAt:      time.Now(),
		TotalFindings:    1,
		EnrichedFindings: 1,
	})
	require.NoError(t, err)

	// Generate HTML report
	scanIDStr := fmt.Sprintf("%d", scanID)
	generator, err := NewHTMLGeneratorWithDatabase(scanIDStr, db, logger.GetGlobalLogger())
	require.NoError(t, err)

	// Create temp file for output
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.html")

	err = generator.Generate(outputPath)
	require.NoError(t, err)

	// Read and verify the report content
	content, err := os.ReadFile(outputPath) // #nosec G304 - test file path
	require.NoError(t, err)
	html := string(content)

	// Verify the report includes AI enrichments
	assert.Contains(t, html, "GDPR violations")
	assert.Contains(t, html, "Block all public access")
	assert.Contains(t, html, "30 minutes")
	assert.Contains(t, html, "customer data exports")
}

func TestEnrichmentReportSummarySection(t *testing.T) {
	// Create in-memory database
	db, err := database.New(":memory:")
	require.NoError(t, err)
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Logf("failed to close database: %v", closeErr)
		}
	}()

	ctx := context.Background()
	scanID, err := db.CreateScan(ctx, &database.Scan{
		Status:    database.ScanStatusCompleted,
		StartedAt: time.Now().Add(-30 * time.Minute),
	})
	require.NoError(t, err)

	// Create metadata with multiple findings
	metadata := &models.ScanMetadata{
		ClientName:  "acme-corp",
		Environment: "production",
		StartTime:   time.Now().Add(-30 * time.Minute),
		EndTime:     time.Now().Add(-5 * time.Minute),
		Results: map[string]*models.ScanResult{
			"prowler": {
				Scanner: "prowler",
				Findings: []models.Finding{
					{
						ID:       "FINDING-001",
						Scanner:  "prowler",
						Severity: "critical",
						Title:    "Root account without MFA",
						Resource: "arn:aws:iam::123456789012:root",
					},
					{
						ID:       "FINDING-002",
						Scanner:  "prowler",
						Severity: "high",
						Title:    "Security group allows SSH from 0.0.0.0/0",
						Resource: "sg-123456",
					},
					{
						ID:       "FINDING-003",
						Scanner:  "prowler",
						Severity: "medium",
						Title:    "S3 bucket without versioning",
						Resource: "arn:aws:s3:::my-bucket",
					},
				},
			},
			"trivy": {
				Scanner: "trivy",
				Findings: []models.Finding{
					{
						ID:       "FINDING-004",
						Scanner:  "trivy",
						Severity: "critical",
						Title:    "Remote code execution in log4j",
						Resource: "app:latest",
					},
					{
						ID:       "FINDING-005",
						Scanner:  "trivy",
						Severity: "low",
						Title:    "Outdated package version",
						Resource: "redis:6.0",
					},
				},
			},
		},
		Summary: models.ScanSummary{
			TotalFindings: 5,
			BySeverity: map[string]int{
				"critical": 2,
				"high":     1,
				"medium":   1,
				"low":      1,
			},
			ByScanner: map[string]int{
				"prowler": 3,
				"trivy":   2,
			},
		},
	}

	// Save the scan data
	store := storage.NewStorage(db)
	err = store.SaveScanResults(scanID, metadata)
	require.NoError(t, err)

	// Save findings to database
	saveFindingsToDatabase(t, db, scanID, metadata)

	// Add enrichments for critical findings
	enrichments := []enrichment.FindingEnrichment{
		{
			FindingID: "FINDING-001",
			Analysis: enrichment.Analysis{
				BusinessImpact:    "Root account compromise would give attacker full control over entire AWS infrastructure",
				PriorityScore:     1.0,
				PriorityReasoning: "Root account without MFA is the highest security risk",
			},
			Remediation: enrichment.Remediation{
				EstimatedEffort: "15 minutes",
				Immediate:       []string{"Enable MFA on root account immediately"},
			},
		},
		{
			FindingID: "FINDING-004",
			Analysis: enrichment.Analysis{
				BusinessImpact:    "Log4j vulnerability allows remote code execution on application servers",
				PriorityScore:     0.98,
				PriorityReasoning: "Actively exploited vulnerability with public exploits available",
			},
			Remediation: enrichment.Remediation{
				EstimatedEffort: "2 hours",
				Immediate:       []string{"Update log4j to patched version 2.17.0 or later"},
			},
		},
	}

	err = store.SaveEnrichments(scanID, enrichments, &enrichment.Metadata{
		StartedAt:        time.Now().Add(-5 * time.Minute),
		CompletedAt:      time.Now(),
		TotalFindings:    5,
		EnrichedFindings: 2,
		Strategy:         "critical-only",
		Driver:           "claude-cli",
	})
	require.NoError(t, err)

	// Generate HTML report
	scanIDStr := fmt.Sprintf("%d", scanID)
	generator, err := NewHTMLGeneratorWithDatabase(scanIDStr, db, logger.GetGlobalLogger())
	require.NoError(t, err)

	// Create temp file for output
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.html")

	err = generator.Generate(outputPath)
	require.NoError(t, err)

	// Read and verify the report content
	content, err := os.ReadFile(outputPath) // #nosec G304 - test file path
	require.NoError(t, err)
	html := string(content)

	// Verify summary section
	assert.Contains(t, html, "acme-corp")
	assert.Contains(t, html, "production")
	assert.Contains(t, html, "5") // Total findings
	assert.Contains(t, html, "2") // Critical findings
	assert.Contains(t, html, "critical-only")
	assert.Contains(t, html, "claude-cli")

	// Verify priority findings are highlighted
	assert.Contains(t, html, "Root account without MFA")
	assert.Contains(t, html, "Remote code execution in log4j")
}
