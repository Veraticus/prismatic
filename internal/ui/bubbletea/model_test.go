package bubbletea

import (
	"errors"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/stretchr/testify/assert"
)

func TestModel_Update_RepoStatusMsg(t *testing.T) {
	tests := []struct {
		expectedIndex map[string]int
		msg           RepoStatusMsg
		name          string
		expectedRepos []RepoState
		initialModel  Model
	}{
		{
			name: "add new repository",
			initialModel: Model{
				repos:     []RepoState{},
				repoIndex: make(map[string]int),
			},
			msg: RepoStatusMsg{
				Name:      "test-repo",
				Status:    RepoStatusPending,
				LocalPath: "",
				Error:     nil,
			},
			expectedRepos: []RepoState{
				{
					Name:   "test-repo",
					Status: RepoStatusPending,
				},
			},
			expectedIndex: map[string]int{"test-repo": 0},
		},
		{
			name: "update existing repository to cloning",
			initialModel: Model{
				repos: []RepoState{
					{Name: "test-repo", Status: RepoStatusPending},
				},
				repoIndex: map[string]int{"test-repo": 0},
			},
			msg: RepoStatusMsg{
				Name:   "test-repo",
				Status: RepoStatusCloning,
			},
			expectedRepos: []RepoState{
				{
					Name:   "test-repo",
					Status: RepoStatusCloning,
				},
			},
			expectedIndex: map[string]int{"test-repo": 0},
		},
		{
			name: "update repository with error",
			initialModel: Model{
				repos: []RepoState{
					{Name: "test-repo", Status: RepoStatusCloning},
				},
				repoIndex: map[string]int{"test-repo": 0},
			},
			msg: RepoStatusMsg{
				Name:  "test-repo",
				Error: errors.New("clone failed"),
			},
			expectedRepos: []RepoState{
				{
					Name:   "test-repo",
					Status: RepoStatusFailed,
					Error:  "clone failed",
				},
			},
			expectedIndex: map[string]int{"test-repo": 0},
		},
		{
			name: "complete repository with path",
			initialModel: Model{
				repos: []RepoState{
					{Name: "test-repo", Status: RepoStatusCloning},
				},
				repoIndex: map[string]int{"test-repo": 0},
			},
			msg: RepoStatusMsg{
				Name:      "test-repo",
				Status:    RepoStatusReady,
				LocalPath: "/path/to/repo",
			},
			expectedRepos: []RepoState{
				{
					Name:      "test-repo",
					Status:    RepoStatusReady,
					LocalPath: "/path/to/repo",
				},
			},
			expectedIndex: map[string]int{"test-repo": 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up initial model
			model := tt.initialModel
			if model.errors == nil {
				model.errors = NewRingBuffer[ErrorEntry](5)
			}

			// Update model
			updatedModel, cmd := model.Update(tt.msg)
			m, ok := updatedModel.(Model)
			assert.True(t, ok)

			// Verify no command is returned
			assert.Nil(t, cmd)

			// Verify repos state
			assert.Equal(t, len(tt.expectedRepos), len(m.repos))
			for i, expectedRepo := range tt.expectedRepos {
				actualRepo := m.repos[i]
				assert.Equal(t, expectedRepo.Name, actualRepo.Name)
				assert.Equal(t, expectedRepo.Status, actualRepo.Status)
				assert.Equal(t, expectedRepo.LocalPath, actualRepo.LocalPath)
				assert.Equal(t, expectedRepo.Error, actualRepo.Error)
			}

			// Verify index
			assert.Equal(t, tt.expectedIndex, m.repoIndex)
		})
	}
}

func TestModel_Update_ScannerStatusMsg(t *testing.T) {
	tests := []struct {
		expectedIndex    map[string]int
		msg              ScannerStatusMsg
		name             string
		expectedScanners []ScannerState
		initialModel     Model
	}{
		{
			name: "add new scanner",
			initialModel: Model{
				scanners:     []ScannerState{},
				scannerIndex: make(map[string]int),
			},
			msg: ScannerStatusMsg{
				Scanner: "trivy",
				Status: &models.ScannerStatus{
					Scanner: "trivy",
					Status:  models.StatusPending,
				},
			},
			expectedScanners: []ScannerState{
				{
					Name:   "trivy",
					Status: ScannerStatusPending,
				},
			},
			expectedIndex: map[string]int{"trivy": 0},
		},
		{
			name: "update scanner to running with progress",
			initialModel: Model{
				scanners: []ScannerState{
					{Name: "trivy", Status: ScannerStatusPending},
				},
				scannerIndex: map[string]int{"trivy": 0},
			},
			msg: ScannerStatusMsg{
				Scanner: "trivy",
				Status: &models.ScannerStatus{
					Status:  models.StatusRunning,
					Message: "Scanning containers...",
					Current: 5,
					Total:   10,
				},
			},
			expectedScanners: []ScannerState{
				{
					Name:    "trivy",
					Status:  ScannerStatusRunning,
					Message: "Scanning containers...",
					Progress: Progress{
						Current: 5,
						Total:   10,
						Percent: 50,
					},
				},
			},
			expectedIndex: map[string]int{"trivy": 0},
		},
		{
			name: "complete scanner with findings",
			initialModel: Model{
				scanners: []ScannerState{
					{Name: "trivy", Status: ScannerStatusRunning},
				},
				scannerIndex: map[string]int{"trivy": 0},
			},
			msg: ScannerStatusMsg{
				Scanner: "trivy",
				Status: &models.ScannerStatus{
					Status:        models.StatusSuccess,
					TotalFindings: 25,
					FindingCounts: map[string]int{
						"critical": 5,
						"high":     10,
						"medium":   10,
					},
				},
			},
			expectedScanners: []ScannerState{
				{
					Name:   "trivy",
					Status: ScannerStatusSuccess,
					Findings: FindingSummary{
						Total: 25,
						BySeverity: map[string]int{
							"critical": 5,
							"high":     10,
							"medium":   10,
						},
					},
				},
			},
			expectedIndex: map[string]int{"trivy": 0},
		},
		{
			name: "fail scanner with error message",
			initialModel: Model{
				scanners: []ScannerState{
					{Name: "trivy", Status: ScannerStatusRunning},
				},
				scannerIndex: map[string]int{"trivy": 0},
			},
			msg: ScannerStatusMsg{
				Scanner: "trivy",
				Status: &models.ScannerStatus{
					Status:  models.StatusFailed,
					Message: "Scanner error: permission denied",
				},
			},
			expectedScanners: []ScannerState{
				{
					Name:    "trivy",
					Status:  ScannerStatusFailed,
					Message: "Scanner error: permission denied",
				},
			},
			expectedIndex: map[string]int{"trivy": 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up initial model
			model := tt.initialModel
			if model.errors == nil {
				model.errors = NewRingBuffer[ErrorEntry](5)
			}

			// Update model
			updatedModel, cmd := model.Update(tt.msg)
			m, ok := updatedModel.(Model)
			assert.True(t, ok)

			// Verify no command is returned
			assert.Nil(t, cmd)

			// Verify scanners state
			assert.Equal(t, len(tt.expectedScanners), len(m.scanners))
			for i, expectedScanner := range tt.expectedScanners {
				actualScanner := m.scanners[i]
				assert.Equal(t, expectedScanner.Name, actualScanner.Name)
				assert.Equal(t, expectedScanner.Status, actualScanner.Status)
				assert.Equal(t, expectedScanner.Message, actualScanner.Message)
				assert.Equal(t, expectedScanner.Progress, actualScanner.Progress)
				assert.Equal(t, expectedScanner.Findings, actualScanner.Findings)
			}

			// Verify index
			assert.Equal(t, tt.expectedIndex, m.scannerIndex)
		})
	}
}

func TestModel_Update_ScannerErrorMsg(t *testing.T) {
	model := Model{
		errors: NewRingBuffer[ErrorEntry](5),
	}

	// Add an error
	msg := ScannerErrorMsg{
		Scanner: "trivy",
		Error:   "Failed to connect to Docker daemon",
	}

	updatedModel, cmd := model.Update(msg)
	m, ok := updatedModel.(Model)
	assert.True(t, ok)

	// Verify no command is returned
	assert.Nil(t, cmd)

	// Verify error was added
	errors := m.errors.Items()
	assert.Len(t, errors, 1)
	assert.Equal(t, "trivy", errors[0].Scanner)
	assert.Equal(t, "Failed to connect to Docker daemon", errors[0].Message)
}

func TestModel_Update_FinalSummaryMsg(t *testing.T) {
	model := Model{
		errors: NewRingBuffer[ErrorEntry](5),
	}

	// Send final summary
	msg := FinalSummaryMsg{
		Lines: []string{
			"Scan complete!",
			"Found 42 vulnerabilities",
		},
	}

	updatedModel, cmd := model.Update(msg)
	m, ok := updatedModel.(Model)
	assert.True(t, ok)

	// Verify quit command is returned
	assert.NotNil(t, cmd)

	// Verify final state
	assert.True(t, m.showFinalSummary)
	assert.Equal(t, msg.Lines, m.finalMessage)
}

func TestModel_Update_WindowSizeMsg(t *testing.T) {
	model := Model{
		width:  0,
		height: 0,
		errors: NewRingBuffer[ErrorEntry](5),
	}

	// Update window size
	updatedModel, cmd := model.Update(tea.WindowSizeMsg{
		Width:  120,
		Height: 40,
	})
	m, ok := updatedModel.(Model)
	assert.True(t, ok)

	// Verify no command is returned
	assert.Nil(t, cmd)

	// Verify dimensions updated
	assert.Equal(t, 120, m.width)
	assert.Equal(t, 40, m.height)
}

func TestModel_Update_KeyMsg(t *testing.T) {
	model := Model{
		errors: NewRingBuffer[ErrorEntry](5),
	}

	// Test Ctrl+C
	updatedModel, cmd := model.Update(tea.KeyMsg{
		Type: tea.KeyCtrlC,
	})
	m, ok := updatedModel.(Model)
	assert.True(t, ok)

	// Verify quit command is returned
	assert.NotNil(t, cmd)
	assert.True(t, m.stopped)

	// Test other keys (should be ignored)
	model2 := Model{
		errors: NewRingBuffer[ErrorEntry](5),
	}
	updatedModel2, cmd2 := model2.Update(tea.KeyMsg{
		Type: tea.KeyEnter,
	})

	// Verify no command for other keys
	assert.Nil(t, cmd2)
	m2, ok2 := updatedModel2.(Model)
	assert.True(t, ok2)
	assert.False(t, m2.stopped)
}

func TestModel_Update_TickMsg(t *testing.T) {
	startTime := time.Now().Add(-30 * time.Second)
	model := Model{
		errors: NewRingBuffer[ErrorEntry](5),
		scanners: []ScannerState{
			{
				Name:      "trivy",
				Status:    ScannerStatusRunning,
				StartTime: startTime,
			},
			{
				Name:      "nuclei",
				Status:    ScannerStatusSuccess,
				StartTime: startTime,
				Duration:  20 * time.Second,
			},
		},
		scannerIndex: map[string]int{
			"trivy":  0,
			"nuclei": 1,
		},
	}

	// Send tick
	updatedModel, cmd := model.Update(TickMsg(time.Now()))
	m, ok := updatedModel.(Model)
	assert.True(t, ok)

	// Verify tick command is returned
	assert.NotNil(t, cmd)

	// Verify only running scanner duration was updated
	assert.Greater(t, m.scanners[0].Duration, time.Duration(0))
	assert.Equal(t, 20*time.Second, m.scanners[1].Duration)
}

func TestModel_ParseStatus(t *testing.T) {
	// Test ParseRepoStatus
	assert.Equal(t, RepoStatusPending, ParseRepoStatus("pending"))
	assert.Equal(t, RepoStatusCloning, ParseRepoStatus("cloning"))
	assert.Equal(t, RepoStatusReady, ParseRepoStatus("complete"))
	assert.Equal(t, RepoStatusFailed, ParseRepoStatus("failed"))
	assert.Equal(t, RepoStatusPending, ParseRepoStatus("unknown"))

	// Test ParseScannerStatus
	assert.Equal(t, ScannerStatusPending, ParseScannerStatus(models.StatusPending))
	assert.Equal(t, ScannerStatusStarting, ParseScannerStatus(models.StatusStarting))
	assert.Equal(t, ScannerStatusRunning, ParseScannerStatus(models.StatusRunning))
	assert.Equal(t, ScannerStatusSuccess, ParseScannerStatus(models.StatusSuccess))
	assert.Equal(t, ScannerStatusFailed, ParseScannerStatus(models.StatusFailed))
	assert.Equal(t, ScannerStatusSkipped, ParseScannerStatus(models.StatusSkipped))
	assert.Equal(t, ScannerStatusPending, ParseScannerStatus("unknown"))
}
