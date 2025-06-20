package ui

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/joshsymonds/prismatic/internal/database"
)

func TestFindingDetails_Creation(t *testing.T) {
	fd := NewFindingDetails()

	assert.NotNil(t, fd)
	assert.NotNil(t, fd.viewport)
	assert.Nil(t, fd.finding)
	assert.False(t, fd.ready)
}

func TestFindingDetails_WindowResize(t *testing.T) {
	fd := NewFindingDetails()

	// Initial window size
	_, cmd := fd.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	assert.Nil(t, cmd)

	assert.True(t, fd.ready)
	assert.Equal(t, 100, fd.width)
	assert.Equal(t, 30, fd.height)
	assert.Equal(t, 96, fd.viewport.Width)  // width - 4
	assert.Equal(t, 24, fd.viewport.Height) // height - 6

	// Resize window
	fd.Update(tea.WindowSizeMsg{Width: 80, Height: 25})
	assert.Equal(t, 80, fd.width)
	assert.Equal(t, 25, fd.height)
	assert.Equal(t, 76, fd.viewport.Width)
	assert.Equal(t, 19, fd.viewport.Height)
}

func TestFindingDetails_Navigation(t *testing.T) {
	tests := []struct {
		wantMsg tea.Msg
		name    string
		key     string
	}{
		{
			name:    "escape goes back",
			key:     "esc",
			wantMsg: NavigateToPageMsg{Page: ResultsBrowserPage},
		},
		{
			name:    "q goes back",
			key:     "q",
			wantMsg: NavigateToPageMsg{Page: ResultsBrowserPage},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fd := NewFindingDetails()
			fd.ready = true

			_, cmd := fd.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(tt.key)})
			require.NotNil(t, cmd)

			msg := cmd()
			navMsg, ok := msg.(NavigateToPageMsg)
			require.True(t, ok)
			assert.Equal(t, tt.wantMsg, navMsg)
		})
	}
}

func TestFindingDetails_ViewWithoutFinding(t *testing.T) {
	fd := NewFindingDetails()

	// Before initialization
	view := fd.View()
	assert.Contains(t, view, "Initializing...")

	// After initialization but no finding
	fd.Update(tea.WindowSizeMsg{Width: 80, Height: 25})
	view = fd.View()
	assert.Contains(t, view, "No finding selected")
}

func TestFindingDetails_LoadFinding(t *testing.T) {
	fd := NewFindingDetails()
	fd.Update(tea.WindowSizeMsg{Width: 120, Height: 40})

	finding := createTestFinding()

	// Load finding
	_, cmd := fd.Update(FindingDetailsMsg{Finding: finding})
	assert.Nil(t, cmd)
	assert.Equal(t, finding, fd.finding)

	// Check that content is rendered
	view := fd.View()
	assert.Contains(t, view, finding.Title)
	assert.Contains(t, view, strings.ToUpper(string(finding.Severity)))
}

func TestFindingDetails_RenderContent(t *testing.T) {
	fd := NewFindingDetails()
	fd.width = 120
	fd.height = 40
	fd.ready = true

	finding := createTestFinding()
	fd.finding = finding

	content := fd.renderFindingContent()

	// Check basic sections are rendered
	assert.Contains(t, content, "ID:")
	assert.Contains(t, content, fmt.Sprintf("%d", finding.ID))
	assert.Contains(t, content, "Scanner:")
	assert.Contains(t, content, finding.Scanner)
	assert.Contains(t, content, "Description")
	assert.Contains(t, content, finding.Description)
	assert.Contains(t, content, "Resource:")
	assert.Contains(t, content, finding.Resource)
	assert.Contains(t, content, "Severity:")
	assert.Contains(t, content, string(finding.Severity))
}

func TestFindingDetails_TechnicalDetails(t *testing.T) {
	fd := NewFindingDetails()
	fd.width = 120
	fd.ready = true

	finding := createTestFinding()
	technicalData := map[string]any{
		"vulnerability": "SQL Injection",
		"cwe":           []string{"CWE-89"},
		"owasp":         "A03:2021",
	}
	technical, _ := json.Marshal(technicalData)
	finding.TechnicalDetails = technical
	fd.finding = finding

	content := fd.renderTechnicalDetails()

	assert.Contains(t, content, "Technical Details")
	assert.Contains(t, content, "vulnerability")
	assert.Contains(t, content, "SQL Injection")
	assert.Contains(t, content, "cwe")
	assert.Contains(t, content, "CWE-89")
}

func TestFindingDetails_MaskSecret(t *testing.T) {
	tests := []struct {
		name     string
		secret   string
		expected string
	}{
		{
			name:     "short secret",
			secret:   "abc123",
			expected: "******",
		},
		{
			name:     "long secret",
			secret:   "ghp_1234567890abcdef",
			expected: "ghp_************cdef",
		},
		{
			name:     "exact 8 chars",
			secret:   "12345678",
			expected: "********",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			masked := maskSecret(tt.secret)
			assert.Equal(t, tt.expected, masked)
		})
	}
}

func TestFindingDetails_GetSeverityStyle(t *testing.T) {
	tests := []struct {
		severity string
		hasColor bool
	}{
		{"CRITICAL", true},
		{"HIGH", true},
		{"MEDIUM", true},
		{"LOW", true},
		{"INFO", true},
		{"unknown", true},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			style := getSeverityStyle(tt.severity)
			// Just verify we get a style back
			rendered := style.Render(tt.severity)
			assert.NotEmpty(t, rendered)
		})
	}
}

func TestFindingDetails_KeyboardShortcuts(t *testing.T) {
	fd := NewFindingDetails()
	fd.ready = true
	fd.finding = createTestFinding()

	tests := []struct {
		name string
		key  string
		// For now, just verify no panic
	}{
		{"suppress key", "s"},
		{"copy key", "c"},
		{"export key", "e"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			// Should not panic
			_, _ = fd.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(tt.key)})
		})
	}
}

func TestFindingDetails_Footer(t *testing.T) {
	fd := NewFindingDetails()
	fd.width = 120

	footer := fd.renderFooter()

	// Check shortcuts are displayed
	assert.Contains(t, footer, "[ESC/q] Back")
	assert.Contains(t, footer, "[↑↓/j/k] Scroll")
	assert.Contains(t, footer, "[s] Suppress")
	assert.Contains(t, footer, "[c] Copy ID")
	assert.Contains(t, footer, "[e] Export")
}

// Helper function to create a test finding.
func createTestFinding() *database.Finding {
	return &database.Finding{
		ID:               123,
		ScanID:           1,
		Scanner:          "gitleaks",
		Severity:         database.SeverityCritical,
		Title:            "Hard-coded GitHub Token Detected",
		Description:      "A GitHub personal access token was found hard-coded in the source code.",
		Resource:         "main.py:42",
		TechnicalDetails: nil,
		CreatedAt:        time.Now(),
	}
}
