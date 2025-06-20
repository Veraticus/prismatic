// Package testutil provides testing utilities for TUI components.
package testutil

import (
	"context"
	"database/sql"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/require"

	"github.com/joshsymonds/prismatic/internal/database"
	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/joshsymonds/prismatic/internal/ui"
)

// CreateTestScan creates a test scan in the database.
func CreateTestScan(t *testing.T, db *database.DB, profile string, status database.ScanStatus) *database.Scan {
	t.Helper()

	scan := &database.Scan{
		AWSProfile: sql.NullString{String: profile, Valid: true},
		Status:     status,
		Scanners:   database.ScannerTrivy | database.ScannerProwler,
		AWSRegions: []string{"us-east-1"},
	}

	ctx := context.Background()
	scanID, err := db.CreateScan(ctx, scan)
	require.NoError(t, err)

	scan.ID = scanID
	return scan
}

// CreateTestFindings creates test findings for a scan.
func CreateTestFindings(t *testing.T, db *database.DB, scanID int64, count int) []*database.Finding {
	t.Helper()

	severities := []database.Severity{
		database.SeverityCritical,
		database.SeverityHigh,
		database.SeverityMedium,
		database.SeverityLow,
		database.SeverityInfo,
	}

	scanners := []string{
		database.ScannerNameTrivy,
		database.ScannerNameProwler,
		database.ScannerNameGitleaks,
		database.ScannerNameNuclei,
		database.ScannerNameKubescape,
	}

	findings := make([]*database.Finding, count)
	for i := 0; i < count; i++ {
		findings[i] = &database.Finding{
			ScanID:      scanID,
			Scanner:     scanners[i%len(scanners)],
			Severity:    severities[i%len(severities)],
			Title:       "Test finding " + string(rune('A'+i)),
			Description: "This is a test finding description for finding " + string(rune('A'+i)),
			Resource:    "resource-" + string(rune('1'+i)),
		}
	}

	ctx := context.Background()
	err := db.BatchInsertFindings(ctx, scanID, findings)
	require.NoError(t, err)

	return findings
}

// CreateTestScanHistory creates a test scan history with findings.
func CreateTestScanHistory(t *testing.T, db *database.DB, count int) []ui.ScanHistoryItem {
	t.Helper()

	items := make([]ui.ScanHistoryItem, count)

	for i := 0; i < count; i++ {
		// Create scan
		scan := CreateTestScan(t, db, "test-profile-"+string(rune('A'+i)), database.ScanStatusCompleted)

		// Set timestamps
		scan.StartedAt = time.Now().Add(-time.Duration(count-i) * time.Hour)
		scan.CompletedAt = sql.NullTime{
			Time:  time.Now().Add(-time.Duration(count-i-1) * time.Hour),
			Valid: true,
		}

		// Create findings
		CreateTestFindings(t, db, scan.ID, 10+i*5)

		// Get finding counts
		ctx := context.Background()
		counts, err := db.GetFindingCounts(ctx, scan.ID)
		require.NoError(t, err)

		items[i] = ui.ScanHistoryItem{
			Scan:          scan,
			FindingCounts: counts,
		}
	}

	return items
}

// CreateTestModelsFindings creates test findings using the models package.
func CreateTestModelsFindings(count int) []*models.Finding {
	findings := make([]*models.Finding, count)

	severities := []string{
		models.SeverityCritical,
		models.SeverityHigh,
		models.SeverityMedium,
		models.SeverityLow,
		models.SeverityInfo,
	}

	scanners := []string{"trivy", "prowler", "gitleaks", "nuclei", "kubescape"}

	for i := 0; i < count; i++ {
		findings[i] = &models.Finding{
			ID:             "finding-" + string(rune('A'+i)),
			Scanner:        scanners[i%len(scanners)],
			Severity:       severities[i%len(severities)],
			Title:          "Test finding " + string(rune('A'+i)),
			Description:    "This is a test finding description",
			Resource:       "resource-" + string(rune('1'+i)),
			Type:           "test-type",
			Impact:         "Test impact description",
			Remediation:    "Test remediation steps",
			References:     []string{"https://example.com/ref" + string(rune('1'+i))},
			DiscoveredDate: time.Now(),
			Suppressed:     false,
		}
	}

	return findings
}

// SimulateKeyPress simulates a key press and returns the resulting model and command.
func SimulateKeyPress(model tea.Model, key string) (tea.Model, tea.Cmd) {
	var msg tea.Msg

	switch key {
	case "enter":
		msg = tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		msg = tea.KeyMsg{Type: tea.KeyEsc}
	case "tab":
		msg = tea.KeyMsg{Type: tea.KeyTab}
	case "shift+tab":
		msg = tea.KeyMsg{Type: tea.KeyShiftTab}
	case "up":
		msg = tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		msg = tea.KeyMsg{Type: tea.KeyDown}
	case "left":
		msg = tea.KeyMsg{Type: tea.KeyLeft}
	case "right":
		msg = tea.KeyMsg{Type: tea.KeyRight}
	case "ctrl+c":
		msg = tea.KeyMsg{Type: tea.KeyCtrlC}
	default:
		// Regular key press
		msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)}
	}

	return model.Update(msg)
}

// AssertViewContains checks that a view contains expected strings.
func AssertViewContains(t *testing.T, view string, expected []string) {
	t.Helper()

	for _, exp := range expected {
		if !contains(view, exp) {
			t.Errorf("Expected view to contain %q but it didn't.\nView:\n%s", exp, view)
		}
	}
}

// AssertViewNotContains checks that a view does not contain unexpected strings.
func AssertViewNotContains(t *testing.T, view string, unexpected []string) {
	t.Helper()

	for _, unexp := range unexpected {
		if contains(view, unexp) {
			t.Errorf("Expected view NOT to contain %q but it did.\nView:\n%s", unexp, view)
		}
	}
}

// contains is a helper function to check if a string contains a substring.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && containsAt(s, substr, 0)
}

func containsAt(s, substr string, start int) bool {
	for i := start; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// CreateMemoryDB creates an in-memory database for testing.
func CreateMemoryDB(t *testing.T) *database.DB {
	t.Helper()

	db, err := database.NewMemoryDB()
	require.NoError(t, err)

	t.Cleanup(func() {
		err := db.Close()
		require.NoError(t, err)
	})

	return db
}

// RunUpdate runs an update on a model and returns the updated model.
func RunUpdate(t *testing.T, model tea.Model, msg tea.Msg) tea.Model {
	t.Helper()

	updatedModel, _ := model.Update(msg)
	return updatedModel
}

// CreateTestScannerStatus creates a test scanner status.
func CreateTestScannerStatus(scanner string, status string) *models.ScannerStatus {
	return &models.ScannerStatus{
		Scanner:   scanner,
		Status:    status,
		StartTime: time.Now(),
		FindingCounts: map[string]int{
			"critical": 5,
			"high":     10,
			"medium":   15,
			"low":      20,
		},
		TotalFindings: 50,
	}
}

// CreateTestRepoStatus creates a test repository status message.
func CreateTestRepoStatus(name, status, path string, err error) any {
	// This would return the appropriate message type
	// Implementation depends on the specific message types in your UI
	return struct {
		Error     error
		Name      string
		Status    string
		LocalPath string
	}{
		Name:      name,
		Status:    status,
		LocalPath: path,
		Error:     err,
	}
}
