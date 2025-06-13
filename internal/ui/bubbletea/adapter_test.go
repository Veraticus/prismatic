package bubbletea

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/joshsymonds/prismatic/internal/ui"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	// Set GO_TEST environment variable for all tests
	_ = os.Setenv("GO_TEST", "true")
	code := m.Run()
	os.Exit(code)
}

func TestScannerUIAdapter_Creation(t *testing.T) {
	config := ui.Config{
		OutputDir:   "/tmp/test",
		ClientName:  "TestClient",
		Environment: "test",
		StartTime:   time.Now(),
	}

	adapter := NewScannerUIAdapter(config)
	assert.NotNil(t, adapter)
	assert.NotNil(t, adapter.program)
	assert.NotNil(t, adapter.model)
	assert.Equal(t, config.OutputDir, adapter.model.outputDir)
	assert.Equal(t, config.ClientName, adapter.model.client)
	assert.Equal(t, config.Environment, adapter.model.environment)
}

func TestScannerUIAdapter_UpdateRepository(t *testing.T) {
	adapter := NewScannerUIAdapter(ui.Config{
		OutputDir: "/tmp/test",
		StartTime: time.Now(),
	})

	// Test various repository updates
	tests := []struct {
		err       error
		name      string
		repoName  string
		status    string
		localPath string
	}{
		{
			name:     "pending repository",
			repoName: "repo1",
			status:   "pending",
		},
		{
			name:     "cloning repository",
			repoName: "repo1",
			status:   "cloning",
		},
		{
			name:      "complete repository",
			repoName:  "repo1",
			status:    "complete",
			localPath: "/path/to/repo1",
		},
		{
			name:     "failed repository",
			repoName: "repo2",
			status:   "failed",
			err:      errors.New("clone failed"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			adapter.UpdateRepository(tt.repoName, tt.status, tt.localPath, tt.err)
		})
	}
}

func TestScannerUIAdapter_UpdateScanner(t *testing.T) {
	adapter := NewScannerUIAdapter(ui.Config{
		OutputDir: "/tmp/test",
		StartTime: time.Now(),
	})

	// Test various scanner updates
	tests := []struct {
		status *models.ScannerStatus
		name   string
	}{
		{
			name: "starting scanner",
			status: &models.ScannerStatus{
				Scanner: "trivy",
				Status:  models.StatusStarting,
			},
		},
		{
			name: "running scanner with progress",
			status: &models.ScannerStatus{
				Scanner: "trivy",
				Status:  models.StatusRunning,
				Message: "Scanning containers",
				Current: 5,
				Total:   10,
			},
		},
		{
			name: "completed scanner with findings",
			status: &models.ScannerStatus{
				Scanner:       "trivy",
				Status:        models.StatusSuccess,
				TotalFindings: 25,
				FindingCounts: map[string]int{
					"critical": 5,
					"high":     10,
					"medium":   10,
				},
			},
		},
		{
			name: "failed scanner",
			status: &models.ScannerStatus{
				Scanner: "nuclei",
				Status:  models.StatusFailed,
				Message: "Template download failed",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			adapter.UpdateScanner(tt.status)
		})
	}
}

func TestScannerUIAdapter_AddError(t *testing.T) {
	adapter := NewScannerUIAdapter(ui.Config{
		OutputDir: "/tmp/test",
		StartTime: time.Now(),
	})

	// Add multiple errors
	adapter.AddError("trivy", "Docker daemon not running")
	adapter.AddError("nuclei", "Template parsing failed")
	adapter.AddError("gitleaks", "No git repository found")

	// Should not panic
	assert.NotNil(t, adapter)
}

func TestScannerUIAdapter_IsStopped(t *testing.T) {
	adapter := NewScannerUIAdapter(ui.Config{
		OutputDir: "/tmp/test",
		StartTime: time.Now(),
	})

	// Initially not stopped
	assert.False(t, adapter.IsStopped())

	// Stop the adapter
	adapter.Stop()

	// Should be stopped
	assert.True(t, adapter.IsStopped())

	// Subsequent calls should not panic
	adapter.Stop()
	assert.True(t, adapter.IsStopped())
}

func TestScannerUIAdapter_RenderFinalState(t *testing.T) {
	adapter := NewScannerUIAdapter(ui.Config{
		OutputDir: "/tmp/test",
		StartTime: time.Now(),
	})

	summaryLines := []string{
		"📁 Results saved to: /tmp/test",
		"🎯 Run 'prismatic report --scan latest' to generate report",
	}

	// Should not panic
	adapter.RenderFinalState(summaryLines)
}

func TestScannerUIAdapter_StoppedBehavior(t *testing.T) {
	adapter := NewScannerUIAdapter(ui.Config{
		OutputDir: "/tmp/test",
		StartTime: time.Now(),
	})

	// Stop the adapter
	adapter.Stop()

	// Updates after stopping should be ignored (not panic)
	adapter.UpdateRepository("repo1", "cloning", "", nil)
	adapter.UpdateScanner(&models.ScannerStatus{
		Scanner: "trivy",
		Status:  models.StatusRunning,
	})
	adapter.AddError("test", "This should be ignored")
}

func TestScannerUIAdapter_FullWorkflow(t *testing.T) {
	config := ui.Config{
		OutputDir:   "/tmp/scan-results",
		ClientName:  "ACME Corp",
		Environment: "production",
		StartTime:   time.Now(),
	}

	adapter := NewScannerUIAdapter(config)

	// Simulate a full scan workflow

	// 1. Start UI
	adapter.Start()

	// 2. Repository preparation
	adapter.UpdateRepository("frontend", "pending", "", nil)
	adapter.UpdateRepository("backend", "pending", "", nil)

	adapter.UpdateRepository("frontend", "cloning", "", nil)
	adapter.UpdateRepository("backend", "cloning", "", nil)

	adapter.UpdateRepository("frontend", "complete", "/tmp/repos/frontend", nil)
	adapter.UpdateRepository("backend", "complete", "/tmp/repos/backend", nil)

	// 3. Scanner execution
	scanners := []string{"trivy", "nuclei", "gitleaks"}
	for _, scanner := range scanners {
		status := models.NewScannerStatus(scanner)
		adapter.UpdateScanner(status)
	}

	// Update scanners to running
	for _, scanner := range scanners {
		status := models.NewScannerStatus(scanner)
		status.SetRunning("Initializing...")
		adapter.UpdateScanner(status)
	}

	// Simulate progress
	trivyStatus := models.NewScannerStatus("trivy")
	trivyStatus.SetRunning("Scanning containers")
	trivyStatus.SetProgress(5, 10)
	adapter.UpdateScanner(trivyStatus)

	// Complete trivy with findings
	trivyStatus.SetCompletedWithFindings(15, map[string]int{
		"critical": 2,
		"high":     5,
		"medium":   8,
	})
	adapter.UpdateScanner(trivyStatus)

	// Fail gitleaks
	gitleaksStatus := models.NewScannerStatus("gitleaks")
	gitleaksStatus.SetFailed(errors.New("No git repository found"))
	adapter.UpdateScanner(gitleaksStatus)
	adapter.AddError("gitleaks", "No git repository found")

	// Complete nuclei
	nucleiStatus := models.NewScannerStatus("nuclei")
	nucleiStatus.SetCompleted()
	adapter.UpdateScanner(nucleiStatus)

	// 4. Final summary
	summaryLines := []string{
		"📁 Results saved to: /tmp/scan-results",
		"🎯 Run 'prismatic report --scan latest' to generate report",
	}
	adapter.RenderFinalState(summaryLines)

	// Verify adapter handled everything without panics
	assert.NotNil(t, adapter)
}
