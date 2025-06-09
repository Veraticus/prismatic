package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Veraticus/prismatic/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStorage(t *testing.T) {
	storage := NewStorage("/tmp/test")
	assert.NotNil(t, storage)
	assert.Equal(t, "/tmp/test", storage.baseDir)
}

func TestSaveAndLoadScanResults(t *testing.T) {
	// Create temporary directory for tests
	tempDir := t.TempDir()
	storage := NewStorage(tempDir)

	// Create test data
	metadata := &models.ScanMetadata{
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
				Error:     "simulated error",
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

	// Test saving
	outputDir := filepath.Join(tempDir, "scan-output")
	err := storage.SaveScanResults(outputDir, metadata)
	require.NoError(t, err)

	// Verify files were created
	assert.FileExists(t, filepath.Join(outputDir, "metadata.json"))
	assert.FileExists(t, filepath.Join(outputDir, "findings.json"))
	assert.FileExists(t, filepath.Join(outputDir, "scan.log"))
	assert.FileExists(t, filepath.Join(outputDir, "raw", "mock.json"))
	assert.NoFileExists(t, filepath.Join(outputDir, "raw", "test-scanner.json")) // No raw output for failed scanner

	// Test loading
	loaded, err := storage.LoadScanResults(outputDir)
	require.NoError(t, err)
	assert.Equal(t, metadata.ClientName, loaded.ClientName)
	assert.Equal(t, metadata.Environment, loaded.Environment)
	assert.Equal(t, metadata.Scanners, loaded.Scanners)
	assert.Equal(t, metadata.Summary.TotalFindings, loaded.Summary.TotalFindings)

	// Verify findings.json content
	var findings []models.Finding
	// Path is safe - constructed from test temp directory
	findingsData, err := os.ReadFile(filepath.Join(outputDir, "findings.json")) // #nosec G304
	require.NoError(t, err)
	err = json.Unmarshal(findingsData, &findings)
	require.NoError(t, err)
	assert.Len(t, findings, 1)
	assert.Equal(t, "finding-1", findings[0].ID)

	// Verify scan.log content
	// Path is safe - constructed from test temp directory
	logContent, err := os.ReadFile(filepath.Join(outputDir, "scan.log")) // #nosec G304
	require.NoError(t, err)
	assert.Contains(t, string(logContent), "Client: test-client")
	assert.Contains(t, string(logContent), "Environment: test-env")
	assert.Contains(t, string(logContent), "✓ mock")
	assert.Contains(t, string(logContent), "✗ test-scanner")
	assert.Contains(t, string(logContent), "Total Findings: 1")
	assert.Contains(t, string(logContent), "high: 1")
	assert.Contains(t, string(logContent), "Failed Scanners:")
	assert.Contains(t, string(logContent), "Error: simulated error")
}

func TestSaveAndLoadJSON(t *testing.T) {
	tempDir := t.TempDir()
	storage := NewStorage(tempDir)

	testData := struct {
		Name  string
		Items []string
		Value int
	}{
		Name:  "test",
		Value: 42,
		Items: []string{"one", "two", "three"},
	}

	// Save JSON
	jsonPath := filepath.Join(tempDir, "test.json")
	err := storage.saveJSON(jsonPath, testData)
	require.NoError(t, err)

	// Load JSON
	var loaded struct {
		Name  string
		Items []string
		Value int
	}
	err = storage.loadJSON(jsonPath, &loaded)
	require.NoError(t, err)

	assert.Equal(t, testData.Name, loaded.Name)
	assert.Equal(t, testData.Value, loaded.Value)
	assert.Equal(t, testData.Items, loaded.Items)
}

func TestFindLatestScan(t *testing.T) {
	tempDir := t.TempDir()
	storage := NewStorage(tempDir)

	// Test with no scans directory
	_, err := storage.FindLatestScan()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no scans found")

	// Create scans directory with some scan directories
	scansDir := filepath.Join(tempDir, "scans")
	require.NoError(t, os.MkdirAll(scansDir, 0750))

	// Create scan directories with different timestamps
	scanDirs := []string{
		"2024-01-01T10-00-00Z",
		"2024-01-02T10-00-00Z",
		"2024-01-03T10-00-00Z",
		"2024-01-02T15-00-00Z",
	}

	for _, dir := range scanDirs {
		require.NoError(t, os.MkdirAll(filepath.Join(scansDir, dir), 0750))
	}

	// Also create a file (should be ignored)
	require.NoError(t, os.WriteFile(filepath.Join(scansDir, "not-a-directory.txt"), []byte("test"), 0600))

	// Find latest scan
	latest, err := storage.FindLatestScan()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(scansDir, "2024-01-03T10-00-00Z"), latest)

	// Test with empty scans directory
	require.NoError(t, os.RemoveAll(scansDir))
	require.NoError(t, os.MkdirAll(scansDir, 0750))
	_, err = storage.FindLatestScan()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no scan directories found")
}

func TestListScans(t *testing.T) {
	tempDir := t.TempDir()
	storage := NewStorage(tempDir)

	// Create scans directory
	scansDir := filepath.Join(tempDir, "scans")
	require.NoError(t, os.MkdirAll(scansDir, 0750))

	// Create test scans
	testScans := []struct {
		dir      string
		metadata models.ScanMetadata
	}{
		{
			dir: "2024-01-01T10-00-00Z",
			metadata: models.ScanMetadata{
				ClientName:  "client-a",
				Environment: "prod",
				StartTime:   time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC),
				EndTime:     time.Date(2024, 1, 1, 10, 30, 0, 0, time.UTC),
				Summary: models.ScanSummary{
					TotalFindings: 10,
				},
			},
		},
		{
			dir: "2024-01-02T10-00-00Z",
			metadata: models.ScanMetadata{
				ClientName:  "client-b",
				Environment: "dev",
				StartTime:   time.Date(2024, 1, 2, 10, 0, 0, 0, time.UTC),
				EndTime:     time.Date(2024, 1, 2, 10, 30, 0, 0, time.UTC),
				Summary: models.ScanSummary{
					TotalFindings: 5,
				},
			},
		},
		{
			dir: "2024-01-03T10-00-00Z",
			metadata: models.ScanMetadata{
				ClientName:  "client-a",
				Environment: "staging",
				StartTime:   time.Date(2024, 1, 3, 10, 0, 0, 0, time.UTC),
				EndTime:     time.Date(2024, 1, 3, 10, 30, 0, 0, time.UTC),
				Summary: models.ScanSummary{
					TotalFindings: 15,
				},
			},
		},
	}

	// Create scan directories with metadata
	for _, scan := range testScans {
		scanDir := filepath.Join(scansDir, scan.dir)
		require.NoError(t, os.MkdirAll(scanDir, 0750))
		require.NoError(t, storage.saveJSON(filepath.Join(scanDir, "metadata.json"), scan.metadata))
	}

	// Also create an invalid directory (should be skipped)
	invalidDir := filepath.Join(scansDir, "invalid-scan")
	require.NoError(t, os.MkdirAll(invalidDir, 0750))
	require.NoError(t, os.WriteFile(filepath.Join(invalidDir, "metadata.json"), []byte("invalid json"), 0600))

	// Test listing all scans
	scans, err := storage.ListScans("", 0)
	require.NoError(t, err)
	assert.Len(t, scans, 3)

	// Should be in reverse chronological order
	assert.Equal(t, "2024-01-03T10-00-00Z", scans[0].ID)
	assert.Equal(t, "client-a", scans[0].ClientName)
	assert.Equal(t, "staging", scans[0].Environment)
	assert.Equal(t, 15, scans[0].Summary.TotalFindings)

	assert.Equal(t, "2024-01-02T10-00-00Z", scans[1].ID)
	assert.Equal(t, "client-b", scans[1].ClientName)

	assert.Equal(t, "2024-01-01T10-00-00Z", scans[2].ID)

	// Test filtering by client
	scans, err = storage.ListScans("client-a", 0)
	require.NoError(t, err)
	assert.Len(t, scans, 2)
	assert.Equal(t, "client-a", scans[0].ClientName)
	assert.Equal(t, "client-a", scans[1].ClientName)

	// Test limit
	scans, err = storage.ListScans("", 2)
	require.NoError(t, err)
	assert.Len(t, scans, 2)
	assert.Equal(t, "2024-01-03T10-00-00Z", scans[0].ID)
	assert.Equal(t, "2024-01-02T10-00-00Z", scans[1].ID)

	// Test with non-existent directory
	storage2 := NewStorage("/non/existent/path")
	_, err = storage2.ListScans("", 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reading scans directory")
}

func TestConsolidateFindings(t *testing.T) {
	storage := NewStorage("")

	metadata := &models.ScanMetadata{
		Results: map[string]*models.ScanResult{
			"scanner1": {
				Findings: []models.Finding{
					{ID: "finding-1", Scanner: "scanner1"},
					{ID: "finding-2", Scanner: "scanner1"},
				},
			},
			"scanner2": {
				Findings: []models.Finding{
					{ID: "finding-3", Scanner: "scanner2"},
				},
			},
			"scanner3": {
				// No findings
			},
		},
	}

	findings := storage.consolidateFindings(metadata)
	assert.Len(t, findings, 3)

	// Verify all findings are present
	foundIDs := make(map[string]bool)
	for _, f := range findings {
		foundIDs[f.ID] = true
	}
	assert.True(t, foundIDs["finding-1"])
	assert.True(t, foundIDs["finding-2"])
	assert.True(t, foundIDs["finding-3"])
}

func TestSaveLoadErrorHandling(t *testing.T) {
	storage := NewStorage("")

	// Test saving to invalid path
	err := storage.SaveScanResults("/invalid\x00path", &models.ScanMetadata{})
	assert.Error(t, err)

	// Test loading from non-existent directory
	_, err = storage.LoadScanResults("/non/existent/path")
	assert.Error(t, err)

	// Test loading invalid JSON
	tempDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "metadata.json"), []byte("invalid json"), 0600))
	_, err = storage.LoadScanResults(tempDir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "loading metadata")
}

func TestLoadScanResultsWithMissingFindings(t *testing.T) {
	tempDir := t.TempDir()
	storage := NewStorage(tempDir)

	// Create metadata without findings file
	metadata := &models.ScanMetadata{
		ClientName:  "test-client",
		Environment: "test",
		StartTime:   time.Now(),
		EndTime:     time.Now(),
	}

	metadataPath := filepath.Join(tempDir, "metadata.json")
	require.NoError(t, storage.saveJSON(metadataPath, metadata))

	// Load should succeed even without findings file
	loaded, err := storage.LoadScanResults(tempDir)
	require.NoError(t, err)
	assert.Equal(t, metadata.ClientName, loaded.ClientName)
	assert.NotNil(t, loaded.Results) // Should initialize empty map
}

func TestSaveJSONWithInvalidPath(t *testing.T) {
	storage := NewStorage("")

	// Test with invalid path
	err := storage.saveJSON("/invalid\x00path/file.json", struct{}{})
	assert.Error(t, err)
}

func TestLoadJSONWithInvalidPath(t *testing.T) {
	storage := NewStorage("")

	var data struct{}
	err := storage.loadJSON("/non/existent/file.json", &data)
	assert.Error(t, err)
}
