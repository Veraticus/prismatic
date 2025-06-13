package bubbletea

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestModel_View_NoWidth(t *testing.T) {
	model := Model{
		width: 0,
	}

	view := model.View()
	assert.Equal(t, "Initializing...", view)
}

func TestModel_View_Header(t *testing.T) {
	model := Model{
		width:       80,
		startTime:   time.Now().Add(-1 * time.Minute),
		outputDir:   "/tmp/scan-results",
		client:      "TestClient",
		environment: "production",
		errors:      NewRingBuffer[ErrorEntry](5),
	}

	view := model.View()

	// Check header content
	assert.Contains(t, view, "Prismatic Security Scanner")
	assert.Contains(t, view, "Output: /tmp/scan-results")
	assert.Contains(t, view, "Client: TestClient")
	assert.Contains(t, view, "Environment: production")
	assert.Contains(t, view, "Elapsed: 1m0s")
}

func TestModel_View_Repositories(t *testing.T) {
	model := Model{
		width: 80,
		repos: []RepoState{
			{Name: "repo1", Status: RepoStatusPending},
			{Name: "repo2", Status: RepoStatusCloning},
			{Name: "repo3", Status: RepoStatusReady, LocalPath: "/path/to/repo3"},
			{Name: "repo4", Status: RepoStatusFailed, Error: "clone failed"},
		},
		errors: NewRingBuffer[ErrorEntry](5),
	}

	view := model.View()

	// Check repository section
	assert.Contains(t, view, "Repository Preparation")
	assert.Contains(t, view, "repo1: Pending")
	assert.Contains(t, view, "repo2: Cloning...")
	assert.Contains(t, view, "repo3: Ready")
	assert.Contains(t, view, "repo4: Failed: clone failed")
}

func TestModel_View_Scanners(t *testing.T) {
	model := Model{
		width: 80,
		scanners: []ScannerState{
			{
				Name:     "trivy",
				Status:   ScannerStatusRunning,
				Duration: 30 * time.Second,
				Progress: Progress{Current: 5, Total: 10, Percent: 50},
				Message:  "Scanning containers",
			},
			{
				Name:     "nuclei",
				Status:   ScannerStatusSuccess,
				Duration: 45 * time.Second,
				Findings: FindingSummary{
					Total: 15,
					BySeverity: map[string]int{
						"critical": 2,
						"high":     5,
						"medium":   8,
					},
				},
			},
			{
				Name:     "gitleaks",
				Status:   ScannerStatusFailed,
				Duration: 10 * time.Second,
				Message:  "No git repository found",
			},
		},
		errors: NewRingBuffer[ErrorEntry](5),
	}

	view := model.View()

	// Check scanner section
	assert.Contains(t, view, "Scanner Status")
	assert.Contains(t, view, "Scanner")
	assert.Contains(t, view, "Status")
	assert.Contains(t, view, "Time")
	assert.Contains(t, view, "Progress")

	// Check specific scanner statuses
	assert.Contains(t, view, "trivy")
	assert.Contains(t, view, "Running")
	assert.Contains(t, view, "30s")
	assert.Contains(t, view, "[5/10] Scanning containers")

	assert.Contains(t, view, "nuclei")
	assert.Contains(t, view, "Complete")
	assert.Contains(t, view, "45s")
	assert.Contains(t, view, "15 findings: 2 crit, 5 high, 8 med")

	assert.Contains(t, view, "gitleaks")
	assert.Contains(t, view, "Failed")
	assert.Contains(t, view, "10s")
	assert.Contains(t, view, "No git repository found")
}

func TestModel_View_Summary(t *testing.T) {
	model := Model{
		width: 80,
		scanners: []ScannerState{
			{
				Name:   "trivy",
				Status: ScannerStatusSuccess,
				Findings: FindingSummary{
					Total: 20,
					BySeverity: map[string]int{
						"critical": 5,
						"high":     10,
						"medium":   5,
					},
				},
			},
			{
				Name:   "nuclei",
				Status: ScannerStatusSuccess,
				Findings: FindingSummary{
					Total: 10,
					BySeverity: map[string]int{
						"high":   2,
						"medium": 3,
						"low":    5,
					},
				},
			},
		},
		errors: NewRingBuffer[ErrorEntry](5),
	}

	view := model.View()

	// Check summary section
	assert.Contains(t, view, "Finding Summary")
	assert.Contains(t, view, "Total: 30")
	assert.Contains(t, view, "Critical: 5")
	assert.Contains(t, view, "High: 12")
	assert.Contains(t, view, "Medium: 8")
	assert.Contains(t, view, "Low: 5")
}

func TestModel_View_Errors(t *testing.T) {
	model := Model{
		width:  80,
		errors: NewRingBuffer[ErrorEntry](5),
		infoMaxHeight: 10,
	}

	// Add some errors
	model.errors.Add(ErrorEntry{
		Scanner: "trivy",
		Message: "Docker daemon not running",
	})
	model.errors.Add(ErrorEntry{
		Scanner: "nuclei",
		Message: "Template download failed",
	})

	view := model.View()

	// Check error section
	assert.Contains(t, view, "Recent Errors")
	assert.Contains(t, view, "[trivy] Docker daemon not running")
	assert.Contains(t, view, "[nuclei] Template download failed")
}

func TestModel_View_FinalSummary(t *testing.T) {
	model := Model{
		width:            80,
		showFinalSummary: true,
		finalMessage: []string{
			"📁 Results saved to: /tmp/scan-123",
			"🎯 Run 'prismatic report --scan latest' to generate report",
		},
		errors: NewRingBuffer[ErrorEntry](5),
		infoMaxHeight: 10,
	}

	view := model.View()

	// Check final summary
	assert.Contains(t, view, "✨ Scan Complete!")
	assert.Contains(t, view, "Results saved to: /tmp/scan-123")
	assert.Contains(t, view, "Run 'prismatic report --scan latest' to generate report")
}

func TestModel_getBoxWidth(t *testing.T) {
	tests := []struct {
		name     string
		width    int
		expected int
	}{
		{
			name:     "narrow terminal",
			width:    60,
			expected: 58, // 60 - 2 for margins
		},
		{
			name:     "normal terminal",
			width:    100,
			expected: 98, // 100 - 2 for margins
		},
		{
			name:     "wide terminal",
			width:    150,
			expected: 120, // capped at 120
		},
		{
			name:     "exactly 120",
			width:    122,
			expected: 120, // 122 - 2 = 120
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := Model{width: tt.width}
			assert.Equal(t, tt.expected, model.getBoxWidth())
		})
	}
}

func TestModel_formatDuration(t *testing.T) {
	model := Model{}

	tests := []struct {
		duration time.Duration
		expected string
	}{
		{duration: 0, expected: "-"},
		{duration: 30 * time.Second, expected: "30s"},
		{duration: 59 * time.Second, expected: "59s"},
		{duration: 60 * time.Second, expected: "1m0s"},
		{duration: 90 * time.Second, expected: "1m30s"},
		{duration: 125 * time.Second, expected: "2m5s"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, model.formatDuration(tt.duration))
	}
}

func TestModel_View_EmptySections(t *testing.T) {
	// Test with no repositories
	model := Model{
		width:  80,
		errors: NewRingBuffer[ErrorEntry](5),
	}

	view := model.View()
	assert.NotContains(t, view, "Repository Preparation")

	// Test with no scanners
	assert.NotContains(t, view, "Scanner Status")

	// Test with no errors
	assert.NotContains(t, view, "Recent Errors")
}

func TestModel_View_EdgeCaseWidth(t *testing.T) {
	// Test at exactly 120 terminal width (known edge case from requirements)
	model := Model{
		width:       120,
		startTime:   time.Now(),
		outputDir:   "/tmp/scan",
		client:      "TestClient",
		environment: "prod",
		scanners: []ScannerState{
			{
				Name:     "trivy",
				Status:   ScannerStatusRunning,
				Duration: 30 * time.Second,
				Progress: Progress{Current: 50, Total: 100},
				Message:  "This is a very long message that might cause wrapping issues in the terminal display",
			},
		},
		errors: NewRingBuffer[ErrorEntry](5),
	}

	view := model.View()

	// Ensure view renders without panic
	assert.NotEmpty(t, view)

	// Check that lines don't exceed expected width
	lines := strings.Split(view, "\n")
	for _, line := range lines {
		// Check that no line is excessively long
		// We use a more lenient check since lipgloss may add box characters
		assert.LessOrEqual(t, len(line), 400, "Line exceeds maximum allowed width: %s", line)
	}
}
