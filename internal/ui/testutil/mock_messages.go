package testutil

import (
	"time"

	"github.com/joshsymonds/prismatic/internal/database"
	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/joshsymonds/prismatic/internal/ui"
)

// MockMessage types for testing TUI components.

// MockScannerTickMsg simulates a scanner tick message.
type MockScannerTickMsg time.Time

// MockScannerStatusMsg simulates a scanner status update.
type MockScannerStatusMsg struct {
	Status *models.ScannerStatus
}

// MockRepoStatusMsg simulates a repository status update.
type MockRepoStatusMsg struct {
	Error     error
	Name      string
	Status    string
	LocalPath string
}

// MockScannerErrorMsg simulates a scanner error.
type MockScannerErrorMsg struct {
	Scanner string
	Message string
}

// MockFindingMsg simulates a finding discovery.
type MockFindingMsg struct {
	Finding *models.Finding
}

// MockScanCompleteMsg simulates scan completion.
type MockScanCompleteMsg struct {
	Summary []string
}

// MockLoadScansMsg simulates loading scan history.
type MockLoadScansMsg struct {
	Err   error
	Scans []ui.ScanHistoryItem
}

// MockLoadFindingsMsg simulates loading findings.
type MockLoadFindingsMsg struct {
	Err      error
	Findings []*database.Finding
}

// MockSetScanMsg simulates setting a current scan.
type MockSetScanMsg struct {
	Scan *database.Scan
}

// MockNavigateToPageMsg simulates page navigation.
type MockNavigateToPageMsg struct {
	Data any
	Page string
}

// MockFindingDetailsMsg simulates navigating to finding details.
type MockFindingDetailsMsg struct {
	Finding *database.Finding
}

// CreateMockMessages creates a set of mock messages for testing.
func CreateMockMessages() map[string]any {
	return map[string]any{
		"scanner_tick": MockScannerTickMsg(time.Now()),
		"scanner_status": MockScannerStatusMsg{
			Status: CreateTestScannerStatus("trivy", "running"),
		},
		"repo_status": MockRepoStatusMsg{
			Name:      "test-repo",
			Status:    "cloning",
			LocalPath: "/tmp/test-repo",
		},
		"scanner_error": MockScannerErrorMsg{
			Scanner: "trivy",
			Message: "Failed to scan image",
		},
		"finding": MockFindingMsg{
			Finding: CreateTestModelsFindings(1)[0],
		},
		"scan_complete": MockScanCompleteMsg{
			Summary: []string{"Scan completed successfully"},
		},
		"load_scans": MockLoadScansMsg{
			Scans: []ui.ScanHistoryItem{},
			Err:   nil,
		},
		"load_findings": MockLoadFindingsMsg{
			Findings: []*database.Finding{},
			Err:      nil,
		},
	}
}
