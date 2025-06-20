package ui_test

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/joshsymonds/prismatic/internal/database"
	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/joshsymonds/prismatic/internal/ui"
	"github.com/joshsymonds/prismatic/internal/ui/testutil"
)

// TestRealTimeScanWorkflow simulates a complete scan with real-time updates.
func TestRealTimeScanWorkflow(t *testing.T) {
	db := testutil.CreateMemoryDB(t)

	// Create scan progress page
	scanProgress := ui.NewScanProgress("acme-corp", "production", "/tmp/scans")
	scanProgress.SetDatabase(db)
	scanProgress.SetSize(120, 40)

	// Create initial scan record
	ctx := context.Background()
	scan := &database.Scan{
		AWSProfile: sql.NullString{String: "acme-prod", Valid: true},
		AWSRegions: []string{"us-east-1", "us-west-2"},
		Status:     database.ScanStatusRunning,
		Scanners:   database.ScannerTrivy | database.ScannerProwler | database.ScannerGitleaks,
	}
	scanID, err := db.CreateScan(ctx, scan)
	require.NoError(t, err)
	scan.ID = scanID
	scanProgress.SetScan(scan)

	// Initialize scan progress
	cmd := scanProgress.Init()
	assert.NotNil(t, cmd)

	// Simulate scanner lifecycle
	scanners := []struct {
		name     string
		findings int
		duration time.Duration
	}{
		{"trivy", 25, 2 * time.Second},
		{"prowler", 40, 3 * time.Second},
		{"gitleaks", 5, 1 * time.Second},
	}

	var wg sync.WaitGroup

	// Start scanners concurrently
	for _, scanner := range scanners {
		wg.Add(1)
		go func(s struct {
			name     string
			findings int
			duration time.Duration
		}) {
			defer wg.Done()

			// Scanner starting
			status := &models.ScannerStatus{
				Scanner:   s.name,
				Status:    models.StatusStarting,
				StartTime: time.Now(),
			}
			scanProgress.Update(ui.ScannerStatusMsg{Status: status})

			// Scanner running
			time.Sleep(100 * time.Millisecond)
			status.SetRunning("Scanning repositories...")
			scanProgress.Update(ui.ScannerStatusMsg{Status: status})

			// Discover findings progressively
			for i := 0; i < s.findings; i++ {
				finding := &models.Finding{
					ID:          models.GenerateFindingID(s.name, "security", generateResourceName(s.name, i), fmt.Sprintf("%s-%d", s.name, i)),
					Scanner:     s.name,
					Severity:    getSeverityByIndex(i),
					Title:       generateFindingTitle(s.name, i),
					Description: "Test finding description",
					Resource:    generateResourceName(s.name, i),
					Type:        "security",
					Impact:      "Potential security risk",
					Remediation: "Apply security patch",
				}

				scanProgress.Update(ui.FindingMsg{Finding: finding})

				// Update progress
				status.SetProgress(i+1, s.findings)
				scanProgress.Update(ui.ScannerStatusMsg{Status: status})

				// Small delay between findings
				time.Sleep(s.duration / time.Duration(s.findings))
			}

			// Scanner completed
			status.SetCompletedWithFindings(s.findings, map[string]int{
				"critical": s.findings / 5,
				"high":     s.findings / 4,
				"medium":   s.findings / 3,
				"low":      s.findings - (s.findings/5 + s.findings/4 + s.findings/3),
			})
			scanProgress.Update(ui.ScannerStatusMsg{Status: status})
		}(scanner)
	}

	// Wait for all scanners to complete
	wg.Wait()

	// Give time for all findings to be processed
	time.Sleep(200 * time.Millisecond)

	// Send scan complete message
	summary := []string{
		"Scan completed successfully",
		"Total findings: 70",
		"Scanners completed: 3/3",
		"Duration: 3 seconds",
	}
	scanProgress.Update(ui.ScanCompleteMsg{Summary: summary})

	// Give time for final flush
	time.Sleep(200 * time.Millisecond)

	// Verify final state
	view := scanProgress.View()
	testutil.AssertViewContains(t, view, []string{
		"Prismatic Security Scanner",
		"trivy",
		"prowler",
		"gitleaks",
		"✓", // Success indicator
	})

	// Verify database state
	finalScan, err := db.GetScan(ctx, scanID)
	require.NoError(t, err)
	assert.Equal(t, database.ScanStatusCompleted, finalScan.Status)
	assert.True(t, finalScan.CompletedAt.Valid)

	// Verify findings were saved
	findings, err := db.GetFindings(ctx, scanID, database.FindingFilter{})
	require.NoError(t, err)
	assert.Len(t, findings, 70)

	// Verify finding distribution by scanner
	scannerStats, err := db.GetScannerStats(ctx, scanID)
	require.NoError(t, err)
	assert.Equal(t, 25, scannerStats["trivy"].Total)
	assert.Equal(t, 40, scannerStats["prowler"].Total)
	assert.Equal(t, 5, scannerStats["gitleaks"].Total)
}

// TestScanWithErrors tests scan behavior when errors occur.
func TestScanWithErrors(t *testing.T) {
	db := testutil.CreateMemoryDB(t)

	scanProgress := ui.NewScanProgress("test-client", "staging", "/tmp/scans")
	scanProgress.SetDatabase(db)
	scanProgress.SetSize(120, 40)

	// Create scan
	ctx := context.Background()
	scan := &database.Scan{
		Status:   database.ScanStatusRunning,
		Scanners: database.ScannerTrivy | database.ScannerNuclei,
	}
	scanID, err := db.CreateScan(ctx, scan)
	require.NoError(t, err)
	scan.ID = scanID
	scanProgress.SetScan(scan)

	// Simulate scanner with error
	scanProgress.Update(ui.ScannerErrorMsg{
		Scanner: "trivy",
		Message: "Failed to scan image: connection timeout",
	})

	// Simulate partial success
	status := &models.ScannerStatus{
		Scanner:   "nuclei",
		Status:    models.StatusSuccess,
		StartTime: time.Now(),
	}
	status.SetCompletedWithFindings(10, nil)
	scanProgress.Update(ui.ScannerStatusMsg{Status: status})

	// Complete scan with errors
	summary := []string{
		"Scan completed with errors",
		"1 scanner failed",
		"10 findings discovered",
	}
	scanProgress.Update(ui.ScanCompleteMsg{Summary: summary})

	view := scanProgress.View()
	testutil.AssertViewContains(t, view, []string{
		"Failed to scan image",
		"trivy",
		"Recent Errors",
	})
}

// TestConcurrentScanUpdates tests handling of concurrent updates.
func TestConcurrentScanUpdates(t *testing.T) {
	db := testutil.CreateMemoryDB(t)

	scanProgress := ui.NewScanProgress("test", "test", "/tmp")
	scanProgress.SetDatabase(db)

	// Create scan
	ctx := context.Background()
	scan := &database.Scan{
		Status:   database.ScanStatusRunning,
		Scanners: database.ScannerTrivy,
	}
	scanID, err := db.CreateScan(ctx, scan)
	require.NoError(t, err)
	scan.ID = scanID
	scanProgress.SetScan(scan)

	// Send many updates rapidly but sequentially
	findingCount := 100

	// Send findings in batches to simulate concurrent behavior
	// but ensure they're processed sequentially
	for i := 0; i < findingCount; i++ {
		finding := &models.Finding{
			Scanner:     "trivy",
			Severity:    models.SeverityHigh,
			Title:       fmt.Sprintf("Finding %d", i),
			Description: "Test",
			Resource:    "resource",
		}

		scanProgress.Update(ui.FindingMsg{Finding: finding})

		// Small delay every 10 findings to allow processing
		if i%10 == 9 {
			time.Sleep(10 * time.Millisecond)
		}
	}

	// Give time for all findings to be processed
	time.Sleep(100 * time.Millisecond)

	// Force flush by completing scan
	scanProgress.Update(ui.ScanCompleteMsg{Summary: []string{"Done"}})

	// Give more time for the database flush to complete
	time.Sleep(200 * time.Millisecond)

	// Verify all findings were saved
	findings, err := db.GetFindings(ctx, scanID, database.FindingFilter{Limit: 200})
	require.NoError(t, err)
	assert.Len(t, findings, findingCount)
}

// TestScanProgressPersistence tests that scan progress persists across restarts.
func TestScanProgressPersistence(t *testing.T) {
	db := testutil.CreateMemoryDB(t)
	ctx := context.Background()

	// Create initial scan with some findings
	scan := &database.Scan{
		Status:   database.ScanStatusRunning,
		Scanners: database.ScannerTrivy,
	}
	scanID, err := db.CreateScan(ctx, scan)
	require.NoError(t, err)

	// Add some findings directly to database
	_ = testutil.CreateTestFindings(t, db, scanID, 20)

	// Create new scan progress instance (simulating restart)
	scanProgress := ui.NewScanProgress("test", "test", "/tmp")
	scanProgress.SetDatabase(db)

	// Load existing scan
	existingScan, err := db.GetScan(ctx, scanID)
	require.NoError(t, err)
	scanProgress.SetScan(existingScan)

	// Add more findings
	for i := 0; i < 10; i++ {
		finding := &models.Finding{
			Scanner:     "trivy",
			Severity:    models.SeverityMedium,
			Title:       "New finding after restart",
			Description: "Test",
			Resource:    "new-resource",
		}
		scanProgress.Update(ui.FindingMsg{Finding: finding})
	}

	// Complete scan
	scanProgress.Update(ui.ScanCompleteMsg{Summary: []string{"Resumed scan completed"}})

	// Verify total findings
	allFindings, err := db.GetFindings(ctx, scanID, database.FindingFilter{Limit: 50})
	require.NoError(t, err)
	assert.Len(t, allFindings, 30) // 20 existing + 10 new
}

// Helper functions

func getSeverityByIndex(index int) string {
	severities := []string{
		models.SeverityCritical,
		models.SeverityHigh,
		models.SeverityMedium,
		models.SeverityLow,
		models.SeverityInfo,
	}
	return severities[index%len(severities)]
}

func generateFindingTitle(scanner string, index int) string {
	titles := map[string][]string{
		"trivy": {
			"CVE-2023-1234 in libssl",
			"Outdated package: express@4.17.1",
			"Security misconfiguration in Dockerfile",
		},
		"prowler": {
			"S3 bucket public access enabled",
			"IAM user without MFA",
			"EC2 instance with public IP",
		},
		"gitleaks": {
			"AWS access key exposed",
			"Private key in repository",
			"API token hardcoded",
		},
	}

	scannerTitles := titles[scanner]
	if scannerTitles == nil {
		return "Generic finding"
	}

	return scannerTitles[index%len(scannerTitles)]
}

func generateResourceName(scanner string, index int) string {
	resources := map[string][]string{
		"trivy": {
			"app.jar",
			"node_modules/",
			"Dockerfile",
		},
		"prowler": {
			"arn:aws:s3:::my-bucket",
			"arn:aws:iam::123456789012:user/admin",
			"i-0123456789abcdef0",
		},
		"gitleaks": {
			"config/secrets.yml",
			"src/main.go",
			".env",
		},
	}

	scannerResources := resources[scanner]
	if scannerResources == nil {
		return "unknown-resource"
	}

	return scannerResources[index%len(scannerResources)]
}
