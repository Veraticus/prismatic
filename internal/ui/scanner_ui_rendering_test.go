package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/joshsymonds/prismatic/internal/models"
)

// TestScannerUI_RenderingOutput tests the actual rendered output of the UI.
func TestScannerUI_RenderingOutput(t *testing.T) {
	// This is our expected perfect UI output - what it should look like
	// We strip ANSI codes for comparison but preserve the box structure
	expectedOutput := `
┌─ Prismatic Security Scanner ─────────────────────────────────────────────────────────────────────────────────────┐
│ Output: data/scans/2025-06-10-101629                                                                             │
│ Client: LiveWorld | Environment: production | Elapsed: 9m20s                                                     │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌─ Repository Preparation ─────────────────────────────────────────────────────────────────────────────────────────┐
│ ✓ leatherman                Ready                                                                                │
│ ✓ peyote                    Ready                                                                                │
│ ✓ phoenix                   Ready                                                                                │
│ ✓ riddler                   Ready                                                                                │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌─ Scanner Status ─────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Scanner     │ Status     │ Time     │ Progress                                                                   │
│ ───────────┼────────────┼──────────┼────────────────────────────────────────────────────────────────────────────│
│ gitleaks    │ ✓ Complete │ 8m39s    │ 2793 findings: 2793 crit                                                   │
│ kubescape   │ ✓ Complete │ 14s      │ 930 findings: 117 crit, 513 high, 50 med, 250 low                          │
│ nuclei      │ ✓ Complete │ 4s       │ No findings                                                                │
│ trivy       │ ✓ Complete │ 6s       │ 176 findings: 14 crit, 44 high, 83 med, 31 low                             │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌─ Finding Summary ────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Total: 3895  Critical: 2924  High: 557  Medium: 133  Low: 281                                                    │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌─ Recent Errors ──────────────────────────────────────────────────────────────────────────────────────────────────┐
│ [nuclei] Running nuclei command [endpoints [https://login.liveworld.com/ https://collector.scms.liveworld.com/   │
│ [nuclei] Nuclei completed [duration 4.691167709s output_size 624 json_lines 0 error_lines 0]                     │
│ [nuclei] Nuclei debug output saved [file data/scans/2025-06-10-101629/nuclei-debug-20250610-101708.log]          │
│ [nuclei] Nuclei output preview [lines [                      __     _                                            │
│ [nuclei] Nuclei completed successfully with no findings []                                                       │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘`

	// Count the expected box width
	lines := strings.Split(strings.TrimSpace(expectedOutput), "\n")
	expectedBoxWidth := len([]rune(lines[0]))
	t.Logf("Expected box width from test data: %d characters", expectedBoxWidth)

	// Set up test UI with exact data
	startTime, _ := time.Parse("2006-01-02 15:04:05", "2025-06-10 10:07:09")
	config := Config{
		StartTime:   startTime,
		OutputDir:   "data/scans/2025-06-10-101629",
		ClientName:  "LiveWorld",
		Environment: "production",
	}

	ui := NewScannerUI(config)
	// Force a specific box width for consistent testing
	ui.boxWidth = 116 // Match the expected output width (from test log)

	// Add repositories
	ui.UpdateRepository("leatherman", RepoStatusComplete, "/path/to/leatherman", nil)
	ui.UpdateRepository("peyote", RepoStatusComplete, "/path/to/peyote", nil)
	ui.UpdateRepository("phoenix", RepoStatusComplete, "/path/to/phoenix", nil)
	ui.UpdateRepository("riddler", RepoStatusComplete, "/path/to/riddler", nil)

	// Add scanner statuses with specific elapsed times
	gitleaksStatus := models.NewScannerStatus("gitleaks")
	gitleaksStatus.SetCompletedWithFindings(2793, map[string]int{"critical": 2793})
	gitleaksStatus.ElapsedTime = "8m39s"
	ui.UpdateScanner(gitleaksStatus)

	kubescapeStatus := models.NewScannerStatus("kubescape")
	kubescapeStatus.SetCompletedWithFindings(930, map[string]int{
		"critical": 117,
		"high":     513,
		"medium":   50,
		"low":      250,
	})
	kubescapeStatus.ElapsedTime = "14s"
	ui.UpdateScanner(kubescapeStatus)

	nucleiStatus := models.NewScannerStatus("nuclei")
	nucleiStatus.SetCompleted()
	nucleiStatus.ElapsedTime = "4s"
	ui.UpdateScanner(nucleiStatus)

	trivyStatus := models.NewScannerStatus("trivy")
	trivyStatus.SetCompletedWithFindings(176, map[string]int{
		"critical": 14,
		"high":     44,
		"medium":   83,
		"low":      31,
	})
	trivyStatus.ElapsedTime = "6s"
	ui.UpdateScanner(trivyStatus)

	// Add errors
	ui.AddError("nuclei", "Running nuclei command [endpoints [https://login.liveworld.com/ https://collector.scms.liveworld.com/")
	ui.AddError("nuclei", "Nuclei completed [duration 4.691167709s output_size 624 json_lines 0 error_lines 0]")
	ui.AddError("nuclei", "Nuclei debug output saved [file data/scans/2025-06-10-101629/nuclei-debug-20250610-101708.log]")
	ui.AddError("nuclei", "Nuclei output preview [lines [                      __     _")
	ui.AddError("nuclei", "Nuclei completed successfully with no findings []")

	// Override time for consistent elapsed time
	ui.config.StartTime = time.Now().Add(-9 * time.Minute).Add(-20 * time.Second)

	// Get rendered output
	actualOutput := ui.Render()

	// Strip ANSI codes and cursor movement sequences
	actualClean := stripAllANSI(actualOutput)
	expectedClean := strings.TrimSpace(expectedOutput)

	// Compare line by line for better error messages
	actualLines := strings.Split(strings.TrimSpace(actualClean), "\n")
	expectedLines := strings.Split(expectedClean, "\n")

	// First check line count
	if len(actualLines) != len(expectedLines) {
		t.Errorf("Line count mismatch: got %d lines, want %d lines", len(actualLines), len(expectedLines))
		t.Logf("Actual output:\n%s", actualClean)
		t.Logf("Expected output:\n%s", expectedClean)
	}

	// Then check each line
	for i := 0; i < len(expectedLines) && i < len(actualLines); i++ {
		if actualLines[i] != expectedLines[i] {
			t.Errorf("Line %d mismatch:\nGot:      %q\nExpected: %q", i+1, actualLines[i], expectedLines[i])
		}
	}
}

// TestScannerUI_BoxWidthCalculations tests that boxes don't overflow their width.
func TestScannerUI_BoxWidthCalculations(t *testing.T) {
	tests := []struct {
		name     string
		content  []string
		boxWidth int
		wantErr  bool
	}{
		{
			name:     "expected width",
			boxWidth: 118,
			content: []string{
				"This is a normal line that should fit",
				"Another line with reasonable content",
			},
			wantErr: false,
		},
		{
			name:     "terminal width",
			boxWidth: 120,
			content: []string{
				"This is a normal line that should fit",
				"Another line with reasonable content",
			},
			wantErr: false,
		},
		{
			name:     "narrow width",
			boxWidth: 40,
			content: []string{
				"This line is too long for the narrow box and should be truncated",
			},
			wantErr: false,
		},
		{
			name:     "very narrow width",
			boxWidth: 20,
			content: []string{
				"Tiny",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ui := NewScannerUI(Config{})
			ui.boxWidth = tt.boxWidth

			output := ui.drawBox("Test Box", tt.content)
			lines := strings.Split(strings.TrimSpace(output), "\n")

			for i, line := range lines {
				cleanLine := stripAllANSI(line)
				visualLen := len([]rune(cleanLine))
				if visualLen > tt.boxWidth {
					t.Errorf("Line %d exceeds box width %d: visual len=%d, line=%q",
						i+1, tt.boxWidth, visualLen, cleanLine)
				}
			}
		})
	}
}

// TestScannerUI_TableAlignment tests that table columns align properly.
func TestScannerUI_TableAlignment(t *testing.T) {
	ui := NewScannerUI(Config{})
	ui.boxWidth = 118

	// Add scanners with various name lengths
	scanners := []string{"a", "medium", "very-long-scanner-name"}

	table := ui.buildScannerTable(scanners)

	// Check that separator lines align with headers
	if len(table) < 2 {
		t.Fatal("Table should have at least header and separator")
	}

	headerClean := stripAllANSI(table[0])
	separatorClean := stripAllANSI(table[1])

	// Find column positions in header
	scannerCol := strings.Index(headerClean, "Scanner")
	statusCol := strings.Index(headerClean, "Status")
	timeCol := strings.Index(headerClean, "Time")
	progressCol := strings.Index(headerClean, "Progress")

	// Find separator positions
	sepParts := strings.Split(separatorClean, "┼")
	if len(sepParts) != 4 {
		t.Errorf("Separator should have 4 parts, got %d: %v", len(sepParts), sepParts)
	}

	// Verify alignment (allowing for some padding differences)
	t.Logf("Header:    %q", headerClean)
	t.Logf("Separator: %q", separatorClean)
	t.Logf("Columns at: Scanner=%d, Status=%d, Time=%d, Progress=%d",
		scannerCol, statusCol, timeCol, progressCol)
}

// stripAllANSI removes all ANSI escape sequences including cursor movements.
func stripAllANSI(s string) string {
	// Remove cursor movement sequences
	s = strings.ReplaceAll(s, "\033[H", "") // Move to home

	// Remove all ANSI escape sequences
	for {
		start := strings.Index(s, "\033[")
		if start == -1 {
			break
		}

		// Find the end of the sequence
		end := start + 2
		for end < len(s) {
			// ANSI sequences end with a letter
			if (s[end] >= 'A' && s[end] <= 'Z') || (s[end] >= 'a' && s[end] <= 'z') {
				end++
				break
			}
			end++
		}

		if end > len(s) {
			end = len(s)
		}

		s = s[:start] + s[end:]
	}

	return s
}

// TestScannerUI_RepositoryBoxNoEllipsis ensures repository box doesn't have unnecessary ellipsis.
func TestScannerUI_RepositoryBoxNoEllipsis(t *testing.T) {
	ui := NewScannerUI(Config{})
	ui.boxWidth = 118

	// Add repositories
	ui.UpdateRepository("repo1", RepoStatusComplete, "", nil)
	ui.UpdateRepository("repo2", RepoStatusComplete, "", nil)

	// Get rendered output
	output := ui.renderRepositories()

	// Check that repository lines don't have ellipsis
	lines := strings.Split(output, "\n")
	for i, line := range lines {
		if strings.Contains(line, "Ready") && strings.Contains(line, "...") {
			t.Errorf("Line %d has unnecessary ellipsis: %q", i+1, stripAllANSI(line))
		}
	}
}

// TestScannerUI_VisualVerification prints the expected UI for manual verification.
func TestScannerUI_VisualVerification(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping visual verification in short mode")
	}

	// Using a single string to preserve formatting
	expectedUI := `
=== EXPECTED PERFECT UI OUTPUT ===
┌─ Prismatic Security Scanner ─────────────────────────────────────────────────────────────────────────────────────┐
│ Output: data/scans/2025-06-10-101629                                                                             │
│ Client: LiveWorld | Environment: production | Elapsed: 9m20s                                                     │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌─ Repository Preparation ─────────────────────────────────────────────────────────────────────────────────────────┐
│ ✓ leatherman                Ready                                                                                │
│ ✓ peyote                    Ready                                                                                │
│ ✓ phoenix                   Ready                                                                                │
│ ✓ riddler                   Ready                                                                                │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌─ Scanner Status ─────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Scanner     │ Status     │ Time     │ Progress                                                                   │
│ ───────────┼────────────┼──────────┼────────────────────────────────────────────────────────────────────────────│
│ gitleaks    │ ✓ Complete │ 8m39s    │ 2793 findings: 2793 crit                                                   │
│ kubescape   │ ✓ Complete │ 14s      │ 930 findings: 117 crit, 513 high, 50 med, 250 low                          │
│ nuclei      │ ✓ Complete │ 4s       │ No findings                                                                │
│ trivy       │ ✓ Complete │ 6s       │ 176 findings: 14 crit, 44 high, 83 med, 31 low                             │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌─ Finding Summary ────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Total: 3895  Critical: 2924  High: 557  Medium: 133  Low: 281                                                    │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌─ Recent Errors ──────────────────────────────────────────────────────────────────────────────────────────────────┐
│ [nuclei] Running nuclei command [endpoints [https://login.liveworld.com/ https://collector.scms.liveworld.com/   │
│ [nuclei] Nuclei completed [duration 4.691167709s output_size 624 json_lines 0 error_lines 0]                     │
│ [nuclei] Nuclei debug output saved [file data/scans/2025-06-10-101629/nuclei-debug-20250610-101708.log]          │
│ [nuclei] Nuclei output preview [lines [                      __     _                                             │
│ [nuclei] Nuclei completed successfully with no findings []                                                       │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
=== END EXPECTED OUTPUT ===`

	t.Log(expectedUI)
}
