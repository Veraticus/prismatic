package ui

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Veraticus/prismatic/internal/models"
	"github.com/stretchr/testify/assert"
)

func TestScannerUI_Creation(t *testing.T) {
	config := Config{
		OutputDir:   "/tmp/test",
		ClientName:  "TestClient",
		Environment: "test",
		StartTime:   time.Now(),
	}

	ui := NewScannerUI(config)
	assert.NotNil(t, ui)
	assert.Equal(t, config.OutputDir, ui.config.OutputDir)
	assert.Equal(t, config.ClientName, ui.config.ClientName)
	assert.Equal(t, config.Environment, ui.config.Environment)
	assert.NotNil(t, ui.repoStatuses)
	assert.NotNil(t, ui.scannerStatuses)
	assert.NotNil(t, ui.errorMessages)
}

func TestScannerUI_RepositoryUpdates(t *testing.T) {
	ui := NewScannerUI(Config{
		OutputDir: "/tmp/test",
		StartTime: time.Now(),
	})

	// Test adding new repository
	ui.UpdateRepository("repo1", RepoStatusPending, "", nil)

	repo, exists := ui.repoStatuses["repo1"]
	assert.True(t, exists)
	assert.Equal(t, "repo1", repo.Name)
	assert.Equal(t, RepoStatusPending, repo.Status)

	// Test updating to cloning
	ui.UpdateRepository("repo1", RepoStatusCloning, "", nil)
	repo = ui.repoStatuses["repo1"]
	assert.Equal(t, RepoStatusCloning, repo.Status)

	// Test updating to complete with path
	ui.UpdateRepository("repo1", RepoStatusComplete, "/path/to/repo", nil)
	repo = ui.repoStatuses["repo1"]
	assert.Equal(t, RepoStatusComplete, repo.Status)
	assert.Equal(t, "/path/to/repo", repo.LocalPath)

	// Test failure
	ui.UpdateRepository("repo2", RepoStatusFailed, "", assert.AnError)
	repo = ui.repoStatuses["repo2"]
	assert.Equal(t, RepoStatusFailed, repo.Status)
	assert.Contains(t, repo.Error, "assert.AnError")
}

func TestScannerUI_ScannerUpdates(t *testing.T) {
	ui := NewScannerUI(Config{
		OutputDir: "/tmp/test",
		StartTime: time.Now(),
	})

	// Test adding scanner status
	status := models.NewScannerStatus("trivy")
	status.SetRunning("Scanning containers...")
	ui.UpdateScanner(status)

	savedStatus, exists := ui.scannerStatuses["trivy"]
	assert.True(t, exists)
	assert.Equal(t, models.StatusRunning, savedStatus.Status)
	assert.Equal(t, "Scanning containers...", savedStatus.Message)

	// Test updating with findings
	findingCounts := map[string]int{
		"critical": 5,
		"high":     10,
		"medium":   15,
	}
	status.SetCompletedWithFindings(30, findingCounts)
	ui.UpdateScanner(status)

	savedStatus = ui.scannerStatuses["trivy"]
	assert.Equal(t, models.StatusSuccess, savedStatus.Status)
	assert.Equal(t, 30, savedStatus.TotalFindings)
	assert.Equal(t, 5, savedStatus.FindingCounts["critical"])
}

func TestScannerUI_ErrorMessages(t *testing.T) {
	ui := NewScannerUI(Config{
		OutputDir: "/tmp/test",
		StartTime: time.Now(),
	})

	// Add errors
	for i := 0; i < 7; i++ {
		ui.AddError("test", fmt.Sprintf("Error %d", i))
	}

	// Should only keep last 5
	assert.Len(t, ui.errorMessages, 5)
	assert.Equal(t, "[test] Error 2", ui.errorMessages[0])
	assert.Equal(t, "[test] Error 6", ui.errorMessages[4])
}

func TestScannerUI_BoxDrawing(t *testing.T) {
	ui := NewScannerUI(Config{
		OutputDir: "/tmp/test",
		StartTime: time.Now(),
	})

	// Test box drawing
	box := ui.drawBox("─ Test Box ─", []string{"Line 1", "Line 2"})

	// Strip ANSI codes for testing
	cleanBox := ui.stripANSI(box)
	lines := strings.Split(strings.TrimSpace(cleanBox), "\n")
	assert.Len(t, lines, 4)

	// Check borders
	assert.True(t, strings.HasPrefix(lines[0], "┌"))
	assert.True(t, strings.Contains(lines[0], "Test Box"))
	assert.True(t, strings.HasSuffix(lines[0], "┐"))
	assert.True(t, strings.HasPrefix(lines[1], "│"))
	assert.True(t, strings.HasSuffix(lines[1], "│"))
	assert.True(t, strings.HasPrefix(lines[3], "└"))
	assert.True(t, strings.HasSuffix(lines[3], "┘"))

	// Check content
	assert.Contains(t, lines[1], "Line 1")
	assert.Contains(t, lines[2], "Line 2")
}

func TestScannerUI_StatusIcons(t *testing.T) {
	ui := NewScannerUI(Config{
		OutputDir: "/tmp/test",
		StartTime: time.Now(),
	})

	tests := []struct {
		status string
		want   string
	}{
		{models.StatusPending, "○"},
		{models.StatusStarting, "🚀"},
		{models.StatusRunning, "⟳"},
		{models.StatusSuccess, "✓"},
		{models.StatusFailed, "✗"},
		{models.StatusSkipped, "⏭"},
		{"unknown", "?"},
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			got := ui.getScannerIcon(tt.status)
			// Strip ANSI color codes for comparison
			cleanGot := ui.stripANSI(got)
			assert.Equal(t, tt.want, cleanGot)
		})
	}
}

func TestScannerUI_ProgressFormatting(t *testing.T) {
	ui := NewScannerUI(Config{
		OutputDir: "/tmp/test",
		StartTime: time.Now(),
	})

	tests := []struct {
		name   string
		status *models.ScannerStatus
		want   string
	}{
		{
			name: "failed with message",
			status: &models.ScannerStatus{
				Status:  models.StatusFailed,
				Message: "Connection timeout",
			},
			want: "Connection timeout",
		},
		{
			name: "success no findings",
			status: &models.ScannerStatus{
				Status:        models.StatusSuccess,
				TotalFindings: 0,
			},
			want: "No findings",
		},
		{
			name: "success with findings",
			status: &models.ScannerStatus{
				Status:        models.StatusSuccess,
				TotalFindings: 25,
				FindingCounts: map[string]int{
					"critical": 5,
					"high":     10,
				},
			},
			want: "25 findings: 5 crit, 10 high",
		},
		{
			name: "running with progress",
			status: &models.ScannerStatus{
				Status:  models.StatusRunning,
				Message: "Scanning",
				Current: 50,
				Total:   100,
			},
			want: "[50/100] Scanning",
		},
		{
			name: "initializing",
			status: &models.ScannerStatus{
				Status: models.StatusRunning,
			},
			want: "Initializing...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ui.getScannerProgress(tt.status)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestScannerUI_Truncation(t *testing.T) {
	ui := NewScannerUI(Config{
		OutputDir: "/tmp/test",
		StartTime: time.Now(),
	})

	// Test smartTruncate
	assert.Equal(t, "abc", ui.smartTruncate("abc", 10))
	assert.Equal(t, "abcdefg...", ui.smartTruncate("abcdefghijklmnop", 10))
	assert.Equal(t, "ab", ui.smartTruncate("abcdef", 2))

	// Test padOrTruncate
	assert.Equal(t, "abc       ", ui.padOrTruncate("abc", 10))
	assert.Equal(t, "abcdefg...", ui.padOrTruncate("abcdefghijklmnop", 10))
}

func TestScannerUI_ConcurrentUpdates(t *testing.T) {
	ui := NewScannerUI(Config{
		OutputDir: "/tmp/test",
		StartTime: time.Now(),
	})

	// Test concurrent updates don't cause race conditions
	var wg sync.WaitGroup

	// Update repositories concurrently
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			name := fmt.Sprintf("repo%d", idx)
			ui.UpdateRepository(name, RepoStatusCloning, "", nil)
			ui.UpdateRepository(name, RepoStatusComplete, "/path", nil)
		}(i)
	}

	// Update scanners concurrently
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			scanner := fmt.Sprintf("scanner%d", idx)
			status := models.NewScannerStatus(scanner)
			status.SetRunning("Running...")
			ui.UpdateScanner(status)

			time.Sleep(10 * time.Millisecond)

			status.SetCompleted()
			ui.UpdateScanner(status)
		}(i)
	}

	// Add errors concurrently
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ui.AddError("concurrent", fmt.Sprintf("Error %d", idx))
		}(i)
	}

	wg.Wait()

	// Verify results
	assert.Len(t, ui.repoStatuses, 10)
	assert.Len(t, ui.scannerStatuses, 5)
	assert.Len(t, ui.errorMessages, 5) // Only keeps last 5
}

func TestScannerUI_Rendering(t *testing.T) {
	// Capture stdout during rendering
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	ui := NewScannerUI(Config{
		OutputDir:   "/tmp/test",
		ClientName:  "TestClient",
		Environment: "test",
		StartTime:   time.Now(),
	})

	// Add some data
	ui.UpdateRepository("repo1", RepoStatusComplete, "/path", nil)

	status := models.NewScannerStatus("trivy")
	status.SetCompletedWithFindings(10, map[string]int{"critical": 2})
	ui.UpdateScanner(status)

	ui.AddError("test", "Test error")

	// Trigger render
	ui.render()

	// Restore stdout and read output
	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	// Verify output contains expected elements
	assert.Contains(t, output, "Prismatic Security Scanner")
	assert.Contains(t, output, "TestClient")
	assert.Contains(t, output, "Repository Preparation")
	assert.Contains(t, output, "Scanner Status")
	assert.Contains(t, output, "Finding Summary")
	assert.Contains(t, output, "Recent Errors")
	assert.Contains(t, output, "Test error")
}

func TestScannerUI_StartStop(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	ui := NewScannerUI(Config{
		OutputDir: "/tmp/test",
		StartTime: time.Now(),
	})

	// Start UI
	ui.Start()

	// Give it time to render
	time.Sleep(150 * time.Millisecond)

	// Stop UI
	ui.Stop()

	// Restore stdout
	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	// Should contain clear screen and show cursor sequences
	assert.Contains(t, output, "\033[2J")   // Clear screen
	assert.Contains(t, output, "\033[?25l") // Hide cursor
	assert.Contains(t, output, "\033[?25h") // Show cursor
}
