package ui

import (
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/joshsymonds/prismatic/internal/database"
)

func TestResultsBrowser_Creation(t *testing.T) {
	rb := NewResultsBrowser()

	assert.NotNil(t, rb)
	assert.Empty(t, rb.findings)
	assert.Equal(t, 0, rb.cursor)
	assert.False(t, rb.loading)
	assert.Empty(t, rb.errorMsg)
	assert.Equal(t, 1000, rb.filter.Limit)
}

func TestResultsBrowser_SetScanMessage(t *testing.T) {
	rb := NewResultsBrowser()
	db := &database.DB{} // Mock DB
	rb.SetDatabase(db)

	scan := &database.Scan{
		ID:        123,
		StartedAt: time.Now(),
		Status:    database.ScanStatusCompleted,
	}

	_, cmd := rb.Update(SetScanMsg{Scan: scan})
	assert.Equal(t, scan, rb.currentScan)
	assert.True(t, rb.loading)
	require.NotNil(t, cmd)
}

func TestResultsBrowser_LoadFindingsMessage(t *testing.T) {
	rb := NewResultsBrowser()
	rb.loading = true

	// Test successful load
	findings := []*database.Finding{
		{
			ID:       1,
			Scanner:  "trivy",
			Severity: database.SeverityCritical,
			Title:    "Critical vulnerability",
			Resource: "app.jar",
		},
		{
			ID:       2,
			Scanner:  "gitleaks",
			Severity: database.SeverityHigh,
			Title:    "Exposed secret",
			Resource: "config.yml",
		},
	}

	_, cmd := rb.Update(LoadFindingsMsg{Findings: findings})
	assert.Nil(t, cmd)
	assert.False(t, rb.loading)
	assert.Empty(t, rb.errorMsg)
	assert.Equal(t, findings, rb.findings)

	// Test error handling
	rb.loading = true
	_, cmd = rb.Update(LoadFindingsMsg{Err: assert.AnError})
	assert.Nil(t, cmd)
	assert.False(t, rb.loading)
	assert.Contains(t, rb.errorMsg, "assert.AnError")
}

func TestResultsBrowser_Navigation(t *testing.T) {
	rb := NewResultsBrowser()
	rb.loading = false
	rb.findings = createTestFindings(5)

	tests := []struct {
		name     string
		key      string
		startPos int
		wantPos  int
	}{
		{"down from top", "j", 0, 1},
		{"down at bottom", "j", 4, 4},
		{"up from middle", "k", 2, 1},
		{"up at top", "k", 0, 0},
		{"go to top", "g", 3, 0},
		{"go to bottom", "G", 1, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rb.cursor = tt.startPos
			_, _ = rb.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(tt.key)})
			assert.Equal(t, tt.wantPos, rb.cursor)
		})
	}
}

func TestResultsBrowser_NavigationWhileLoading(t *testing.T) {
	rb := NewResultsBrowser()
	rb.loading = true
	rb.findings = createTestFindings(3)
	initialCursor := rb.cursor

	// All navigation should be ignored while loading
	keys := []string{"j", "k", "g", "G", "enter"}
	for _, key := range keys {
		_, _ = rb.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)})
		assert.Equal(t, initialCursor, rb.cursor)
	}
}

func TestResultsBrowser_EnterKey(t *testing.T) {
	rb := NewResultsBrowser()
	rb.loading = false
	rb.findings = createTestFindings(3)
	rb.cursor = 1

	_, cmd := rb.Update(tea.KeyMsg{Type: tea.KeyEnter})
	require.NotNil(t, cmd)

	msg := cmd()
	detailsMsg, ok := msg.(FindingDetailsMsg)
	require.True(t, ok)
	assert.Equal(t, rb.findings[1], detailsMsg.Finding)
}

func TestResultsBrowser_RefreshKey(t *testing.T) {
	rb := NewResultsBrowser()
	rb.loading = false
	rb.db = &database.DB{} // Mock DB
	rb.currentScan = &database.Scan{ID: 1}

	_, cmd := rb.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("R")})
	assert.True(t, rb.loading)
	require.NotNil(t, cmd)
}

func TestResultsBrowser_View(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*ResultsBrowser)
		contains []string
	}{
		{
			name: "loading state",
			setup: func(rb *ResultsBrowser) {
				rb.loading = true
			},
			contains: []string{"Loading findings..."},
		},
		{
			name: "error state",
			setup: func(rb *ResultsBrowser) {
				rb.loading = false
				rb.errorMsg = "Database connection failed"
			},
			contains: []string{"Error:", "Database connection failed"},
		},
		{
			name: "empty state",
			setup: func(rb *ResultsBrowser) {
				rb.loading = false
				rb.findings = []*database.Finding{}
			},
			contains: []string{"No findings to display"},
		},
		{
			name: "with findings",
			setup: func(rb *ResultsBrowser) {
				rb.loading = false
				rb.findings = createTestFindings(2)
			},
			contains: []string{
				"Results Browser",
				"Total: 2",
				"Critical: 1",
				"High: 1",
				"Severity", "Scanner", "Resource", "Title",
				"CRITICAL", "trivy",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rb := NewResultsBrowser()
			rb.width = 120
			rb.height = 30
			tt.setup(rb)

			view := rb.View()
			for _, expected := range tt.contains {
				assert.Contains(t, view, expected)
			}
		})
	}
}

func TestResultsBrowser_Stats(t *testing.T) {
	rb := NewResultsBrowser()
	rb.findings = []*database.Finding{
		{Severity: database.SeverityCritical},
		{Severity: database.SeverityCritical},
		{Severity: database.SeverityHigh},
		{Severity: database.SeverityMedium},
		{Severity: database.SeverityLow},
		{Severity: database.SeverityLow},
		{Severity: database.SeverityLow},
		{Severity: database.SeverityInfo},
	}

	stats := rb.getStats()
	assert.Equal(t, 8, stats["total"])
	assert.Equal(t, 2, stats["critical"])
	assert.Equal(t, 1, stats["high"])
	assert.Equal(t, 1, stats["medium"])
	assert.Equal(t, 3, stats["low"])
	assert.Equal(t, 1, stats["info"])
}

func TestResultsBrowser_PadRight(t *testing.T) {
	rb := NewResultsBrowser()

	tests := []struct {
		str      string
		expected string
		length   int
	}{
		{"short", "short     ", 10},
		{"exact-len", "exact-len ", 10},
		{"too-long-string", "too-long-…", 10},
	}

	for _, tt := range tests {
		result := rb.padRight(tt.str, tt.length)
		assert.Equal(t, tt.expected, result)
		assert.Equal(t, tt.length, len([]rune(result))) // Ensure exact length
	}
}

func TestResultsBrowser_GetSeverityStyle(t *testing.T) {
	rb := NewResultsBrowser()

	severities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "unknown"}

	for _, severity := range severities {
		style := rb.getSeverityStyle(severity)
		// Just verify we get a style back
		rendered := style.Render(severity)
		assert.NotEmpty(t, rendered)
	}
}

func TestResultsBrowser_SetDatabase(t *testing.T) {
	rb := NewResultsBrowser()
	db := &database.DB{} // Mock DB

	rb.SetDatabase(db)
	assert.Equal(t, db, rb.db)
}

func TestResultsBrowser_SetScan(t *testing.T) {
	rb := NewResultsBrowser()
	scan := &database.Scan{ID: 123}

	rb.SetScan(scan)
	assert.Equal(t, scan, rb.currentScan)
}

// Helper function to create test findings.
func createTestFindings(count int) []*database.Finding {
	findings := make([]*database.Finding, count)
	severities := []database.Severity{
		database.SeverityCritical,
		database.SeverityHigh,
		database.SeverityMedium,
		database.SeverityLow,
		database.SeverityInfo,
	}

	for i := 0; i < count; i++ {
		findings[i] = &database.Finding{
			ID:        int64(i + 1),
			ScanID:    1,
			Scanner:   "trivy",
			Severity:  severities[i%len(severities)],
			Title:     "Test finding " + string(rune('A'+i)),
			Resource:  "resource" + string(rune('1'+i)),
			CreatedAt: time.Now(),
		}
	}
	return findings
}
