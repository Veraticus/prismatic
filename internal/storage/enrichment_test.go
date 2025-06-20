package storage

import (
	"context"
	"testing"
	"time"

	"github.com/joshsymonds/prismatic/internal/database"
	"github.com/joshsymonds/prismatic/internal/enrichment"
	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSaveAndLoadFindingsWithBusinessContext(t *testing.T) {
	// Create in-memory database
	db, err := database.New(":memory:")
	require.NoError(t, err)
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Logf("Failed to close database: %v", closeErr)
		}
	}()

	storage := NewStorage(db)
	ctx := context.Background()

	// Create scan
	scanID, err := db.CreateScan(ctx, &database.Scan{
		Status:    database.ScanStatusCompleted,
		StartedAt: time.Now(),
	})
	require.NoError(t, err)

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
						ID:          "finding-1",
						Scanner:     "prowler",
						Type:        "aws-misconfiguration",
						Severity:    "high",
						Title:       "S3 bucket has public read access",
						Description: "The S3 bucket allows public read access which could expose sensitive data",
						Resource:    "arn:aws:s3:::acme-customer-data",
						BusinessContext: &models.BusinessContext{
							Owner:              "data-team",
							DataClassification: "confidential",
							BusinessImpact:     "Customer PII data exposure",
							ComplianceImpact:   []string{"GDPR", "CCPA violations"},
						},
					},
				},
			},
		},
		Summary: models.ScanSummary{
			TotalFindings: 1,
			BySeverity: map[string]int{
				"high": 1,
			},
		},
	}

	// Save findings to database first
	var dbFindings []*database.Finding
	for _, result := range metadata.Results {
		for _, finding := range result.Findings {
			dbFindings = append(dbFindings, &database.Finding{
				ScanID:      scanID,
				Scanner:     finding.Scanner,
				Severity:    convertSeverityToDatabase(finding.Severity),
				Title:       finding.Title,
				Description: finding.Description,
				Resource:    finding.Resource,
			})
		}
	}
	err = db.BatchInsertFindings(ctx, scanID, dbFindings)
	require.NoError(t, err)

	// Save scan results
	err = storage.SaveScanResults(scanID, metadata)
	require.NoError(t, err)

	// Load and verify
	loaded, err := storage.LoadScanResults(scanID)
	require.NoError(t, err)
	assert.Equal(t, metadata.ClientName, loaded.ClientName)
	assert.Equal(t, metadata.Environment, loaded.Environment)
}

func TestEnrichmentRoundTrip(t *testing.T) {
	// Create in-memory database
	db, err := database.New(":memory:")
	require.NoError(t, err)
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Logf("Failed to close database: %v", closeErr)
		}
	}()

	storage := NewStorage(db)
	ctx := context.Background()

	// Create scan
	scanID, err := db.CreateScan(ctx, &database.Scan{
		Status:    database.ScanStatusCompleted,
		StartedAt: time.Now(),
	})
	require.NoError(t, err)

	// Create enrichments
	enrichments := []enrichment.FindingEnrichment{
		{
			FindingID:  "finding-1",
			EnrichedAt: time.Now(),
			Analysis: enrichment.Analysis{
				BusinessImpact:    "High risk to customer data privacy",
				PriorityScore:     0.95,
				PriorityReasoning: "Exposed S3 bucket contains PII data",
				TechnicalDetails:  "Bucket policy allows s3:GetObject from principal *",
				ContextualNotes:   "This bucket stores daily customer exports",
			},
			Remediation: enrichment.Remediation{
				EstimatedEffort: "30 minutes",
				Immediate: []string{
					"Remove public access from bucket policy",
					"Enable S3 block public access settings",
				},
				ShortTerm: []string{
					"Implement bucket access logging",
					"Set up CloudTrail monitoring",
				},
				LongTerm: []string{
					"Migrate to encrypted S3 with VPC endpoint access only",
				},
			},
			LLMModel:   "claude-3-opus",
			TokensUsed: 1523,
		},
	}

	enrichMeta := &enrichment.Metadata{
		StartedAt:        time.Now().Add(-5 * time.Minute),
		CompletedAt:      time.Now(),
		RunID:            "enrich-001",
		Strategy:         "smart-batch",
		Driver:           "claude-cli",
		LLMModel:         "claude-3-opus",
		TotalFindings:    1,
		EnrichedFindings: 1,
		TotalTokensUsed:  1523,
	}

	// Save enrichments
	err = storage.SaveEnrichments(scanID, enrichments, enrichMeta)
	require.NoError(t, err)

	// Load enrichments
	loadedEnrich, loadedMeta, err := storage.LoadEnrichments(scanID)
	require.NoError(t, err)

	// Verify enrichment data
	require.Len(t, loadedEnrich, 1)
	assert.Equal(t, enrichments[0].FindingID, loadedEnrich[0].FindingID)
	assert.Equal(t, enrichments[0].Analysis.BusinessImpact, loadedEnrich[0].Analysis.BusinessImpact)
	assert.Equal(t, enrichments[0].Analysis.PriorityScore, loadedEnrich[0].Analysis.PriorityScore)
	assert.Equal(t, enrichments[0].Remediation.EstimatedEffort, loadedEnrich[0].Remediation.EstimatedEffort)
	assert.Equal(t, enrichments[0].Remediation.Immediate, loadedEnrich[0].Remediation.Immediate)

	// Verify metadata
	assert.NotNil(t, loadedMeta)
	assert.Equal(t, enrichMeta.TotalFindings, loadedMeta.TotalFindings)
	assert.Equal(t, enrichMeta.EnrichedFindings, loadedMeta.EnrichedFindings)
}

func TestMultipleEnrichmentRuns(t *testing.T) {
	// Create in-memory database
	db, err := database.New(":memory:")
	require.NoError(t, err)
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Logf("Failed to close database: %v", closeErr)
		}
	}()

	storage := NewStorage(db)
	ctx := context.Background()

	// Create scan
	scanID, err := db.CreateScan(ctx, &database.Scan{
		Status:    database.ScanStatusCompleted,
		StartedAt: time.Now(),
	})
	require.NoError(t, err)

	// First enrichment run
	enrichments1 := []enrichment.FindingEnrichment{
		{
			FindingID:  "finding-1",
			EnrichedAt: time.Now().Add(-1 * time.Hour),
			Analysis: enrichment.Analysis{
				BusinessImpact: "Initial analysis",
				PriorityScore:  0.7,
			},
		},
	}

	err = storage.SaveEnrichments(scanID, enrichments1, &enrichment.Metadata{
		StartedAt:        time.Now().Add(-1 * time.Hour),
		CompletedAt:      time.Now().Add(-50 * time.Minute),
		TotalFindings:    1,
		EnrichedFindings: 1,
	})
	require.NoError(t, err)

	// Load and verify we get the enrichments
	loaded, _, err := storage.LoadEnrichments(scanID)
	require.NoError(t, err)
	assert.Len(t, loaded, 1)
	assert.Equal(t, "Initial analysis", loaded[0].Analysis.BusinessImpact)
}
