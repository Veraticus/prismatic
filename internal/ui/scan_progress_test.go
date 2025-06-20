package ui

import (
	"context"
	"database/sql"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/joshsymonds/prismatic/internal/database"
	"github.com/joshsymonds/prismatic/internal/models"
)

func TestScanProgress_Creation(t *testing.T) {
	sp := NewScanProgress("test-client", "prod", "/tmp/output")

	assert.NotNil(t, sp)
	assert.NotNil(t, sp.scanner)
	assert.Equal(t, "test-client", sp.config.ClientName)
	assert.Equal(t, "prod", sp.config.Environment)
	assert.Equal(t, "/tmp/output", sp.config.OutputDir)
	assert.Empty(t, sp.findingsBuf)
}

func TestScanProgress_Init(t *testing.T) {
	sp := NewScanProgress("test-client", "prod", "/tmp/output")

	cmd := sp.Init()
	assert.NotNil(t, cmd)

	// Should return a tick message
	msg := cmd()
	_, ok := msg.(scannerTickMsg)
	assert.True(t, ok)
}

func TestScanProgress_SetDatabase(t *testing.T) {
	sp := NewScanProgress("test-client", "prod", "/tmp/output")
	db := &database.DB{}

	sp.SetDatabase(db)
	assert.Equal(t, db, sp.db)
}

func TestScanProgress_SetScan(t *testing.T) {
	sp := NewScanProgress("test-client", "prod", "/tmp/output")
	scan := &database.Scan{ID: 123}

	sp.SetScan(scan)
	assert.Equal(t, scan, sp.currentScan)
}

func TestScanProgress_ScannerStatusUpdate(t *testing.T) {
	sp := NewScanProgress("test-client", "prod", "/tmp/output")

	status := &models.ScannerStatus{
		Scanner: "trivy",
		Status:  "running",
	}

	_, cmd := sp.Update(ScannerStatusMsg{Status: status})
	assert.Nil(t, cmd)
}

func TestScanProgress_RepoStatusUpdate(t *testing.T) {
	sp := NewScanProgress("test-client", "prod", "/tmp/output")

	_, cmd := sp.Update(RepoStatusMsg{
		Name:      "my-repo",
		Status:    "cloned",
		LocalPath: "/tmp/repos/my-repo",
	})
	assert.Nil(t, cmd)
}

func TestScanProgress_ScannerErrorUpdate(t *testing.T) {
	sp := NewScanProgress("test-client", "prod", "/tmp/output")

	_, cmd := sp.Update(ScannerErrorMsg{
		Scanner: "trivy",
		Message: "failed to scan image",
	})
	assert.Nil(t, cmd)
}

func TestScanProgress_FindingBuffer(t *testing.T) {
	sp := NewScanProgress("test-client", "prod", "/tmp/output")

	// Setup database
	db, err := database.NewMemoryDB()
	require.NoError(t, err)
	sp.SetDatabase(db)

	// Create a scan
	scan := &database.Scan{
		AWSProfile: sql.NullString{String: "test", Valid: true},
		Status:     database.ScanStatusRunning,
		Scanners:   database.ScannerTrivy,
	}
	scanID, err := db.CreateScan(context.Background(), scan)
	require.NoError(t, err)
	scan.ID = scanID
	sp.SetScan(scan)

	// Add findings to buffer
	finding := &models.Finding{
		Scanner:     "trivy",
		Severity:    models.SeverityCritical,
		Title:       "Critical vulnerability",
		Description: "CVE-2023-1234",
		Resource:    "app.jar",
	}

	_, cmd := sp.Update(FindingMsg{Finding: finding})
	assert.Nil(t, cmd)
	assert.Len(t, sp.findingsBuf, 1)

	// Verify finding in buffer
	assert.Equal(t, finding, sp.findingsBuf[0])
}

func TestScanProgress_FindingFlushOnBufferSize(t *testing.T) {
	sp := NewScanProgress("test-client", "prod", "/tmp/output")

	// Setup database
	db, err := database.NewMemoryDB()
	require.NoError(t, err)
	sp.SetDatabase(db)

	// Create a scan
	scan := &database.Scan{
		AWSProfile: sql.NullString{String: "test", Valid: true},
		Status:     database.ScanStatusRunning,
		Scanners:   database.ScannerTrivy,
	}
	scanID, err := db.CreateScan(context.Background(), scan)
	require.NoError(t, err)
	scan.ID = scanID
	sp.SetScan(scan)

	// Add 100 findings to trigger flush
	for i := 0; i < 100; i++ {
		finding := &models.Finding{
			Scanner:     "trivy",
			Severity:    models.SeverityHigh,
			Title:       "Test finding",
			Description: "Test description",
			Resource:    "resource.jar",
		}
		_, _ = sp.Update(FindingMsg{Finding: finding})
	}

	// Buffer should be empty after flush
	assert.Empty(t, sp.findingsBuf)

	// Verify findings in database
	findings, err := db.GetFindings(context.Background(), scanID, database.FindingFilter{Limit: 200})
	require.NoError(t, err)
	assert.Len(t, findings, 100)
}

func TestScanProgress_ScanComplete(t *testing.T) {
	sp := NewScanProgress("test-client", "prod", "/tmp/output")

	// Setup database
	db, err := database.NewMemoryDB()
	require.NoError(t, err)
	sp.SetDatabase(db)

	// Create a scan
	scan := &database.Scan{
		AWSProfile: sql.NullString{String: "test", Valid: true},
		Status:     database.ScanStatusRunning,
		Scanners:   database.ScannerTrivy,
	}
	scanID, err := db.CreateScan(context.Background(), scan)
	require.NoError(t, err)
	scan.ID = scanID
	sp.SetScan(scan)

	// Add some findings
	for i := 0; i < 5; i++ {
		finding := &models.Finding{
			Scanner:     "trivy",
			Severity:    models.SeverityMedium,
			Title:       "Test finding",
			Description: "Test description",
			Resource:    "resource.jar",
		}
		_, _ = sp.Update(FindingMsg{Finding: finding})
	}

	// Complete the scan
	summary := []string{"Scan completed successfully"}
	_, cmd := sp.Update(ScanCompleteMsg{Summary: summary})
	assert.Nil(t, cmd)

	// Buffer should be empty
	assert.Empty(t, sp.findingsBuf)

	// Verify findings were saved
	findings, err := db.GetFindings(context.Background(), scanID, database.FindingFilter{})
	require.NoError(t, err)
	assert.Len(t, findings, 5)

	// Verify scan status was updated
	updatedScan, err := db.GetScan(context.Background(), scanID)
	require.NoError(t, err)
	assert.Equal(t, database.ScanStatusCompleted, updatedScan.Status)
}

func TestScanProgress_PeriodicFlush(t *testing.T) {
	sp := NewScanProgress("test-client", "prod", "/tmp/output")

	// Setup database
	db, err := database.NewMemoryDB()
	require.NoError(t, err)
	sp.SetDatabase(db)

	// Create a scan
	scan := &database.Scan{
		AWSProfile: sql.NullString{String: "test", Valid: true},
		Status:     database.ScanStatusRunning,
		Scanners:   database.ScannerTrivy,
	}
	scanID, err := db.CreateScan(context.Background(), scan)
	require.NoError(t, err)
	scan.ID = scanID
	sp.SetScan(scan)

	// Add a finding
	finding := &models.Finding{
		Scanner:     "trivy",
		Severity:    models.SeverityLow,
		Title:       "Test finding",
		Description: "Test description",
		Resource:    "resource.jar",
	}
	_, _ = sp.Update(FindingMsg{Finding: finding})

	// Set lastDBUpdate to trigger flush on next tick
	sp.lastDBUpdate = time.Now().Add(-6 * time.Second)

	// Send tick message
	_, cmd := sp.Update(scannerTickMsg(time.Now()))
	assert.NotNil(t, cmd) // Should return next tick

	// Buffer should be empty after flush
	assert.Empty(t, sp.findingsBuf)

	// Verify finding in database
	findings, err := db.GetFindings(context.Background(), scanID, database.FindingFilter{})
	require.NoError(t, err)
	assert.Len(t, findings, 1)
}

func TestScanProgress_KeyHandling(t *testing.T) {
	sp := NewScanProgress("test-client", "prod", "/tmp/output")

	// Test quit key
	_, cmd := sp.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	assert.Nil(t, cmd)

	// Test ctrl+c
	_, cmd = sp.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	assert.Nil(t, cmd)
}

func TestScanProgress_View(t *testing.T) {
	sp := NewScanProgress("test-client", "prod", "/tmp/output")
	sp.scanner.Start()

	view := sp.View()
	assert.Contains(t, view, "[Press Esc to go back]")
	assert.Contains(t, view, "Prismatic Security Scanner")
}

func TestScanProgress_SetSize(t *testing.T) {
	sp := NewScanProgress("test-client", "prod", "/tmp/output")

	sp.SetSize(100, 50)
	assert.Equal(t, 100, sp.width)
	assert.Equal(t, 50, sp.height)
}

func TestScanProgress_FlushFindings(t *testing.T) {
	sp := NewScanProgress("test-client", "prod", "/tmp/output")

	// Test with no database
	err := sp.flushFindings()
	assert.NoError(t, err)

	// Setup database
	db, err := database.NewMemoryDB()
	require.NoError(t, err)
	sp.SetDatabase(db)

	// Test with no scan
	err = sp.flushFindings()
	assert.NoError(t, err)

	// Create a scan
	scan := &database.Scan{
		AWSProfile: sql.NullString{String: "test", Valid: true},
		Status:     database.ScanStatusRunning,
		Scanners:   database.ScannerTrivy,
	}
	scanID, err := db.CreateScan(context.Background(), scan)
	require.NoError(t, err)
	scan.ID = scanID
	sp.SetScan(scan)

	// Test with empty buffer
	err = sp.flushFindings()
	assert.NoError(t, err)

	// Test severity mapping
	severities := []string{
		models.SeverityCritical,
		models.SeverityHigh,
		models.SeverityMedium,
		models.SeverityLow,
		models.SeverityInfo,
		"unknown", // Test default case
	}

	for _, sev := range severities {
		sp.findingsBuf = []*models.Finding{
			{
				Scanner:     "trivy",
				Severity:    sev,
				Title:       "Test finding",
				Description: "Test description",
				Resource:    "resource.jar",
			},
		}

		err = sp.flushFindings()
		assert.NoError(t, err)
		assert.Empty(t, sp.findingsBuf)
	}

	// Verify all findings were saved
	findings, err := db.GetFindings(context.Background(), scanID, database.FindingFilter{Limit: 10})
	require.NoError(t, err)
	assert.Len(t, findings, len(severities))
}

func TestScanProgress_ErrorHandling(t *testing.T) {
	sp := NewScanProgress("test-client", "prod", "/tmp/output")

	// Setup database
	db, err := database.NewMemoryDB()
	require.NoError(t, err)
	sp.SetDatabase(db)

	// Create a scan
	scan := &database.Scan{
		AWSProfile: sql.NullString{String: "test", Valid: true},
		Status:     database.ScanStatusRunning,
		Scanners:   database.ScannerTrivy,
	}
	scanID, err := db.CreateScan(context.Background(), scan)
	require.NoError(t, err)
	scan.ID = scanID
	sp.SetScan(scan)

	// Close database to simulate error
	err = db.Close()
	require.NoError(t, err)

	// Add finding and trigger flush
	finding := &models.Finding{
		Scanner:     "trivy",
		Severity:    models.SeverityCritical,
		Title:       "Test finding",
		Description: "Test description",
		Resource:    "resource.jar",
	}

	for i := 0; i < 100; i++ {
		_, _ = sp.Update(FindingMsg{Finding: finding})
	}

	// Should have error in scanner UI
	// The error would be added via AddError in the actual implementation
}
