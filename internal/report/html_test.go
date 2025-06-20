package report

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func TestNewHTMLGenerator(t *testing.T) {
	// Create in-memory database
	db, err := database.New(":memory:")
	require.NoError(t, err)
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Logf("failed to close database: %v", closeErr)
		}
	}()

	// Create test scan data
	ctx := context.Background()
	scanID, err := db.CreateScan(ctx, &database.Scan{
		Status:    database.ScanStatusCompleted,
		StartedAt: time.Now().Add(-10 * time.Minute),
	})
	require.NoError(t, err)

	store := storage.NewStorage(db)

	metadata := &models.ScanMetadata{
		ClientName:  "test-client",
		Environment: "test",
		StartTime:   time.Now().Add(-10 * time.Minute),
		EndTime:     time.Now(),
		Summary: models.ScanSummary{
			TotalFindings: 5,
			BySeverity: map[string]int{
				"critical": 1,
				"high":     2,
				"medium":   2,
			},
		},
		Results: map[string]*models.ScanResult{
			"mock-prowler": {
				Scanner: "mock-prowler",
				Findings: []models.Finding{
					{
						ID:       "finding-1",
						Scanner:  "mock-prowler",
						Type:     "security-group",
						Severity: "critical",
						Title:    "Open Security Group",
						Resource: "sg-12345",
					},
					{
						ID:       "finding-2",
						Scanner:  "mock-prowler",
						Type:     "iam",
						Severity: "high",
						Title:    "Overly Permissive IAM Policy",
						Resource: "arn:aws:iam::123456789012:policy/OverlyPermissive",
					},
				},
			},
		},
	}

	// Save scan data to database
	err = store.SaveScanResults(scanID, metadata)
	require.NoError(t, err)

	// Save findings to database
	saveFindingsToDatabase(t, db, scanID, metadata)

	// Test creating generator with scan ID
	scanIDStr := fmt.Sprintf("%d", scanID)
	gen, err := NewHTMLGeneratorWithDatabase(scanIDStr, db, logger.GetGlobalLogger())
	require.NoError(t, err)
	assert.NotNil(t, gen)
	assert.Equal(t, scanID, gen.scanID)
	assert.Equal(t, "test-client", gen.metadata.ClientName)

	// Test creating generator with "latest"
	gen2, err := NewHTMLGeneratorWithDatabase("latest", db, logger.GetGlobalLogger())
	require.NoError(t, err)
	assert.NotNil(t, gen2)
	assert.Equal(t, scanID, gen2.scanID)
}

func TestHTMLGeneratorGenerate(t *testing.T) {
	// Create in-memory database
	db, err := database.New(":memory:")
	require.NoError(t, err)
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Logf("failed to close database: %v", closeErr)
		}
	}()

	// Create test scan data
	ctx := context.Background()
	scanID, err := db.CreateScan(ctx, &database.Scan{
		Status:    database.ScanStatusCompleted,
		StartedAt: time.Now().Add(-10 * time.Minute),
	})
	require.NoError(t, err)

	store := storage.NewStorage(db)

	metadata := &models.ScanMetadata{
		ClientName:  "test-client",
		Environment: "production",
		StartTime:   time.Now().Add(-10 * time.Minute),
		EndTime:     time.Now(),
		Scanners:    []string{"mock-prowler", "mock-trivy"},
		Summary: models.ScanSummary{
			TotalFindings: 3,
			BySeverity: map[string]int{
				"critical": 1,
				"high":     1,
				"medium":   1,
			},
		},
		Results: map[string]*models.ScanResult{
			"mock-prowler": {
				Scanner: "mock-prowler",
				Findings: []models.Finding{
					{
						ID:          "finding-1",
						Scanner:     "mock-prowler",
						Type:        "security-group",
						Severity:    "critical",
						Title:       "Open Security Group",
						Description: "Security group allows unrestricted access",
						Resource:    "sg-12345",
						Remediation: "Restrict security group rules",
						Metadata: map[string]string{
							"port":     "0-65535",
							"protocol": "all",
							"source":   "0.0.0.0/0",
						},
					},
					{
						ID:          "finding-2",
						Scanner:     "mock-prowler",
						Type:        "iam",
						Severity:    "high",
						Title:       "Overly Permissive IAM Policy",
						Description: "IAM policy grants excessive permissions",
						Resource:    "arn:aws:iam::123456789012:policy/OverlyPermissive",
						Remediation: "Apply least privilege principle",
					},
				},
			},
			"mock-trivy": {
				Scanner: "mock-trivy",
				Findings: []models.Finding{
					{
						ID:          "finding-3",
						Scanner:     "mock-trivy",
						Type:        "vulnerability",
						Severity:    "medium",
						Title:       "Outdated Package",
						Description: "Package has known vulnerabilities",
						Resource:    "nginx:1.14",
						Remediation: "Update to latest version",
					},
				},
			},
		},
	}

	// Save scan data to database
	err = store.SaveScanResults(scanID, metadata)
	require.NoError(t, err)

	// Save findings to database
	saveFindingsToDatabase(t, db, scanID, metadata)

	// Create enrichments
	enrichments := []enrichment.FindingEnrichment{
		{
			FindingID:  "finding-1",
			EnrichedAt: time.Now(),
			Analysis: enrichment.Analysis{
				BusinessImpact:    "Could lead to data breach",
				PriorityScore:     0.95,
				PriorityReasoning: "Internet-facing resource with no restrictions",
			},
			Remediation: enrichment.Remediation{
				EstimatedEffort: "30 minutes",
				Immediate:       []string{"Close security group to specific IPs"},
			},
		},
	}

	err = store.SaveEnrichments(scanID, enrichments, &enrichment.Metadata{
		StartedAt:        time.Now().Add(-5 * time.Minute),
		CompletedAt:      time.Now(),
		TotalFindings:    3,
		EnrichedFindings: 1,
	})
	require.NoError(t, err)

	// Create generator
	scanIDStr := fmt.Sprintf("%d", scanID)
	gen, err := NewHTMLGeneratorWithDatabase(scanIDStr, db, logger.GetGlobalLogger())
	require.NoError(t, err)

	// Generate HTML
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.html")
	err = gen.Generate(outputPath)
	require.NoError(t, err)

	// Read the generated HTML
	content, err := os.ReadFile(outputPath) // #nosec G304 - test file path
	require.NoError(t, err)
	html := string(content)

	// Verify HTML content
	assert.Contains(t, html, "test-client")
	assert.Contains(t, html, "production")
	assert.Contains(t, html, "Open Security Group")
	assert.Contains(t, html, "Overly Permissive IAM Policy")
	assert.Contains(t, html, "Outdated Package")

	// Debug: Check if enrichments are being loaded
	t.Logf("Generated HTML length: %d", len(html))
	if !strings.Contains(html, "Could lead to data breach") {
		// Save HTML for debugging
		debugPath := filepath.Join(tmpDir, "debug.html")
		_ = os.WriteFile(debugPath, []byte(html), 0600) // #nosec G306 - test debug file
		t.Logf("Debug HTML saved to: %s", debugPath)

		// Check enrichments in generator
		t.Logf("Generator enrichments: %+v", gen.enrichments)
	}

	assert.Contains(t, html, "Could lead to data breach") // Enrichment content
}

// TestHTMLGeneratorWithModifications has been removed as modifications functionality is no longer supported
