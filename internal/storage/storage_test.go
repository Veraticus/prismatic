package storage

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/joshsymonds/prismatic/internal/database"
	"github.com/joshsymonds/prismatic/internal/enrichment"
	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// convertSeverityToDatabase converts model severity to database severity format.
func convertSeverityToDatabase(severity string) database.Severity {
	switch severity {
	case "critical":
		return database.SeverityCritical
	case "high":
		return database.SeverityHigh
	case "medium":
		return database.SeverityMedium
	case "low":
		return database.SeverityLow
	case "info":
		return database.SeverityInfo
	default:
		return database.SeverityInfo
	}
}

func TestNewStorage(t *testing.T) {
	db, err := database.New(":memory:")
	require.NoError(t, err)
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Logf("failed to close database: %v", closeErr)
		}
	}()

	storage := NewStorage(db)
	assert.NotNil(t, storage)
	assert.NotNil(t, storage.db)
}

func TestSaveAndLoadScanResults(t *testing.T) {
	// Create in-memory database for tests
	db, err := database.New(":memory:")
	require.NoError(t, err)
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Logf("failed to close database: %v", closeErr)
		}
	}()

	storage := NewStorage(db)

	// Create scan record first
	ctx := context.Background()
	scanID, err := db.CreateScan(ctx, &database.Scan{
		Status:    database.ScanStatusCompleted,
		StartedAt: time.Now(),
	})
	require.NoError(t, err)

	// Create test data
	metadata := &models.ScanMetadata{
		ID:          "test-scan",
		ClientName:  "test-client",
		Environment: "test-env",
		StartTime:   time.Now().Add(-10 * time.Minute),
		EndTime:     time.Now(),
		Scanners:    []string{"mock", "test-scanner"},
		Results: map[string]*models.ScanResult{
			"mock": {
				Scanner:   "mock",
				StartTime: time.Now().Add(-10 * time.Minute),
				EndTime:   time.Now().Add(-5 * time.Minute),
				Findings: []models.Finding{
					{
						ID:          "finding-1",
						Scanner:     "mock",
						Type:        "security",
						Resource:    "test-resource",
						Title:       "Test Finding",
						Description: "Test description",
						Severity:    "high",
						Remediation: "Fix this issue",
						Impact:      "High impact on security",
					},
				},
				RawOutput: []byte(`{"test": "data"}`),
			},
			"test-scanner": {
				Scanner:   "test-scanner",
				StartTime: time.Now().Add(-5 * time.Minute),
				EndTime:   time.Now(),
				Error:     "scanner failed",
			},
		},
		Summary: models.ScanSummary{
			TotalFindings:   1,
			SuppressedCount: 0,
			BySeverity: map[string]int{
				"high": 1,
			},
			FailedScanners: []string{"test-scanner"},
		},
	}

	// Save scan results and findings through scanner interface
	// First save findings directly
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

	// Test saving metadata
	err = storage.SaveScanResults(scanID, metadata)
	require.NoError(t, err)

	// Test loading
	loaded, err := storage.LoadScanResults(scanID)
	require.NoError(t, err)
	assert.Equal(t, metadata.ClientName, loaded.ClientName)
	assert.Equal(t, metadata.Environment, loaded.Environment)
	assert.Equal(t, metadata.Scanners, loaded.Scanners)
	assert.Equal(t, metadata.Summary.TotalFindings, loaded.Summary.TotalFindings)
}

func TestListScans(t *testing.T) {
	// Create in-memory database for tests
	db, err := database.New(":memory:")
	require.NoError(t, err)
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Logf("failed to close database: %v", closeErr)
		}
	}()

	storage := NewStorage(db)
	ctx := context.Background()

	// Create multiple scans
	scan1ID, err := db.CreateScan(ctx, &database.Scan{
		Status:     database.ScanStatusCompleted,
		StartedAt:  time.Now().Add(-2 * time.Hour),
		AWSProfile: sql.NullString{String: "client1", Valid: true},
	})
	require.NoError(t, err)

	scan2ID, err := db.CreateScan(ctx, &database.Scan{
		Status:     database.ScanStatusCompleted,
		StartedAt:  time.Now().Add(-1 * time.Hour),
		AWSProfile: sql.NullString{String: "client2", Valid: true},
	})
	require.NoError(t, err)

	// Save metadata for each scan
	for i, scanID := range []int64{scan1ID, scan2ID} {
		metadata := &models.ScanMetadata{
			ClientName:  "client" + string(rune('1'+i)),
			Environment: "production",
			Summary: models.ScanSummary{
				TotalFindings: 10 * (i + 1),
			},
		}
		err = storage.SaveScanResults(scanID, metadata)
		require.NoError(t, err)
	}

	// Test listing all scans
	scans, err := storage.ListScans("", 10)
	require.NoError(t, err)
	assert.Len(t, scans, 2)

	// Test filtering by client
	scans, err = storage.ListScans("client1", 10)
	require.NoError(t, err)
	assert.Len(t, scans, 1)
	assert.Equal(t, "client1", scans[0].ClientName)
}

func TestFindLatestScan(t *testing.T) {
	// Create in-memory database for tests
	db, err := database.New(":memory:")
	require.NoError(t, err)
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Logf("failed to close database: %v", closeErr)
		}
	}()

	storage := NewStorage(db)
	ctx := context.Background()

	// Test when no scans exist
	_, err = storage.FindLatestScan()
	assert.Error(t, err)

	// Create some scans with distinct times
	// Use time.Date to ensure distinct timestamps
	firstTime := time.Date(2023, 1, 1, 10, 0, 0, 0, time.UTC)
	_, err = db.CreateScan(ctx, &database.Scan{
		Status:    database.ScanStatusCompleted,
		StartedAt: firstTime,
	})
	require.NoError(t, err)

	// Second scan with later time
	latestTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	latestID, err := db.CreateScan(ctx, &database.Scan{
		Status:    database.ScanStatusCompleted,
		StartedAt: latestTime,
	})
	require.NoError(t, err)

	// Test finding latest
	foundID, err := storage.FindLatestScan()
	require.NoError(t, err)

	// Debug: list all scans to see the order
	allScans, err := db.ListScans(ctx, database.ScanFilter{})
	require.NoError(t, err)
	t.Logf("All scans: %+v", allScans)
	for _, s := range allScans {
		t.Logf("Scan %d started at %v", s.ID, s.StartedAt)
	}

	assert.Equal(t, latestID, foundID)
}

func TestSaveAndLoadEnrichments(t *testing.T) {
	// Create in-memory database for tests
	db, err := database.New(":memory:")
	require.NoError(t, err)
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Logf("failed to close database: %v", closeErr)
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

	// Create test enrichments
	enrichments := []enrichment.FindingEnrichment{
		{
			FindingID:  "finding-1",
			EnrichedAt: time.Now(),
			Analysis: enrichment.Analysis{
				BusinessImpact:    "High impact on customer data",
				PriorityScore:     0.8,
				PriorityReasoning: "Critical security issue",
			},
			Remediation: enrichment.Remediation{
				EstimatedEffort: "2 hours",
				Immediate:       []string{"Apply security patch"},
			},
		},
	}

	metadata := &enrichment.Metadata{
		StartedAt:        time.Now().Add(-5 * time.Minute),
		CompletedAt:      time.Now(),
		TotalFindings:    1,
		EnrichedFindings: 1,
		Strategy:         "smart-batch",
		Driver:           "claude-cli",
	}

	// Test saving
	err = storage.SaveEnrichments(scanID, enrichments, metadata)
	require.NoError(t, err)

	// Test loading
	loaded, loadedMeta, err := storage.LoadEnrichments(scanID)
	require.NoError(t, err)
	require.NotNil(t, loadedMeta)
	assert.Len(t, loaded, 2)

	// Verify metadata
	assert.Equal(t, metadata.RunID, loadedMeta.RunID)
	assert.Equal(t, metadata.Strategy, loadedMeta.Strategy)
	assert.Equal(t, metadata.TotalTokensUsed, loadedMeta.TotalTokensUsed)

	// Verify enrichments (order might differ)
	enrichmentMap := make(map[string]enrichment.FindingEnrichment)
	for _, e := range loaded {
		enrichmentMap[e.FindingID] = e
	}

	// Check finding-1
	e1, ok := enrichmentMap["finding-1"]
	assert.True(t, ok)
	assert.Equal(t, "claude-3-opus", e1.LLMModel)
	assert.Equal(t, 1500, e1.TokensUsed)
	assert.Equal(t, 9.5, e1.Analysis.PriorityScore)
	assert.Equal(t, "High risk to customer data security", e1.Analysis.BusinessImpact)
	assert.Len(t, e1.Analysis.RelatedFindings, 2)
	assert.Equal(t, "1 hour", e1.Remediation.EstimatedEffort)
	assert.True(t, e1.Remediation.AutomationPossible)
	assert.Equal(t, "s3", e1.Context["service"])

	// Check finding-2
	e2, ok := enrichmentMap["finding-2"]
	assert.True(t, ok)
	assert.Equal(t, 800, e2.TokensUsed)
	assert.Equal(t, 7.0, e2.Analysis.PriorityScore)
	assert.False(t, e2.Remediation.AutomationPossible)
}

func TestLoadEnrichmentsNoDirectory(t *testing.T) {
	// Test loading enrichments when directory doesn't exist
	tempDir := t.TempDir()
	storage := NewStorage(tempDir)
	scanDir := filepath.Join(tempDir, "scan-002")

	// Create scan directory but no enrichments subdirectory
	require.NoError(t, os.MkdirAll(scanDir, 0750))

	// Should return empty results without error
	enrichments, metadata, err := storage.LoadEnrichments(scanDir)
	require.NoError(t, err)
	assert.Empty(t, enrichments)
	assert.Nil(t, metadata)
}

func TestLoadEnrichmentsInvalidFiles(t *testing.T) {
	// Test handling of invalid enrichment files
	tempDir := t.TempDir()
	storage := NewStorage(tempDir)
	scanDir := filepath.Join(tempDir, "scan-003")
	enrichmentDir := filepath.Join(scanDir, "enrichments")

	require.NoError(t, os.MkdirAll(enrichmentDir, 0750))

	// Create valid metadata
	metadata := &enrichment.EnrichmentMetadata{
		RunID:            "test-run",
		TotalFindings:    5,
		EnrichedFindings: 2,
	}
	metadataPath := filepath.Join(enrichmentDir, "metadata.json")
	data, _ := json.MarshalIndent(metadata, "", "  ")
	require.NoError(t, os.WriteFile(metadataPath, data, 0600))

	// Create one valid enrichment
	validEnrichment := enrichment.FindingEnrichment{
		FindingID:  "valid-finding",
		TokensUsed: 100,
	}
	validData, _ := json.MarshalIndent(validEnrichment, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(enrichmentDir, "valid-finding.json"), validData, 0600))

	// Create invalid JSON file
	require.NoError(t, os.WriteFile(filepath.Join(enrichmentDir, "invalid.json"), []byte("invalid json"), 0600))

	// Create non-JSON file (should be ignored)
	require.NoError(t, os.WriteFile(filepath.Join(enrichmentDir, "readme.txt"), []byte("not json"), 0600))

	// Load should succeed with only valid enrichment
	enrichments, loadedMeta, err := storage.LoadEnrichments(scanDir)
	require.NoError(t, err)
	assert.Len(t, enrichments, 1)
	assert.Equal(t, "valid-finding", enrichments[0].FindingID)
	assert.Equal(t, "test-run", loadedMeta.RunID)
}

func TestSaveEnrichmentsWithInvalidPath(t *testing.T) {
	storage := NewStorage("")

	// Test with invalid scan directory path
	err := storage.SaveEnrichments("/invalid\x00path", []enrichment.FindingEnrichment{}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "creating enrichments directory")
}

func TestLoadEnrichmentsWithInvalidPath(t *testing.T) {
	storage := NewStorage("")

	// Test with invalid scan directory path
	_, _, err := storage.LoadEnrichments("/invalid\x00path")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reading enrichments directory")
}

func TestSaveEnrichmentsPartialFailure(t *testing.T) {
	// Test that saving continues even if some enrichments fail
	tempDir := t.TempDir()
	storage := NewStorage(tempDir)
	scanDir := filepath.Join(tempDir, "scan-004")
	require.NoError(t, os.MkdirAll(scanDir, 0750))

	// Create enrichments with invalid finding ID
	enrichments := []enrichment.FindingEnrichment{
		{
			FindingID:  "valid-finding",
			TokensUsed: 100,
		},
		{
			FindingID:  "invalid/finding", // Contains slash, might cause path issues
			TokensUsed: 200,
		},
	}

	// Should save without error (warnings logged)
	err := storage.SaveEnrichments(scanDir, enrichments, nil)
	require.NoError(t, err)

	// At least the valid enrichment should exist
	enrichmentDir := filepath.Join(scanDir, "enrichments")
	assert.FileExists(t, filepath.Join(enrichmentDir, "valid-finding.json"))
}
