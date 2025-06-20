package ui

import (
	"database/sql"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/joshsymonds/prismatic/internal/database"
)

func TestScanHistory_Creation(t *testing.T) {
	sh := NewScanHistory()

	assert.NotNil(t, sh)
	assert.Empty(t, sh.scans)
	assert.Equal(t, 0, sh.cursor)
	assert.False(t, sh.loading)
	assert.Empty(t, sh.errorMsg)
}

func TestScanHistory_LoadScansMessage(t *testing.T) {
	sh := NewScanHistory()
	sh.loading = true

	// Test successful load
	scans := []ScanHistoryItem{
		{
			Scan: &database.Scan{
				ID:        1,
				StartedAt: time.Now().Add(-1 * time.Hour),
				CompletedAt: sql.NullTime{
					Time:  time.Now(),
					Valid: true,
				},
				Status: database.ScanStatusCompleted,
			},
			FindingCounts: &database.FindingCounts{
				Total:    100,
				Critical: 10,
				High:     20,
			},
		},
	}

	_, cmd := sh.Update(LoadScansMsg{Scans: scans})
	assert.Nil(t, cmd)
	assert.False(t, sh.loading)
	assert.Empty(t, sh.errorMsg)
	assert.Equal(t, scans, sh.scans)

	// Test error handling
	sh.loading = true
	_, cmd = sh.Update(LoadScansMsg{Err: assert.AnError})
	assert.Nil(t, cmd)
	assert.False(t, sh.loading)
	assert.Contains(t, sh.errorMsg, "assert.AnError")
}

func TestScanHistory_Navigation(t *testing.T) {
	sh := NewScanHistory()
	sh.loading = false
	sh.scans = createTestScans(5)

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
			sh.cursor = tt.startPos
			_, _ = sh.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(tt.key)})
			assert.Equal(t, tt.wantPos, sh.cursor)
		})
	}
}

func TestScanHistory_NavigationWhileLoading(t *testing.T) {
	sh := NewScanHistory()
	sh.loading = true
	sh.scans = createTestScans(3)
	initialCursor := sh.cursor

	// All navigation should be ignored while loading
	keys := []string{"j", "k", "g", "G", "enter"}
	for _, key := range keys {
		_, _ = sh.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)})
		assert.Equal(t, initialCursor, sh.cursor)
	}
}

func TestScanHistory_EnterKey(t *testing.T) {
	sh := NewScanHistory()
	sh.loading = false
	sh.scans = createTestScans(3)
	sh.cursor = 1

	_, cmd := sh.Update(tea.KeyMsg{Type: tea.KeyEnter})
	require.NotNil(t, cmd)

	msg := cmd()
	navMsg, ok := msg.(NavigateToPageMsg)
	require.True(t, ok)
	assert.Equal(t, ResultsBrowserPage, navMsg.Page)
}

func TestScanHistory_RefreshKey(t *testing.T) {
	sh := NewScanHistory()
	sh.loading = false

	_, cmd := sh.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("R")})
	assert.True(t, sh.loading)
	require.NotNil(t, cmd)

	// The command should be loadScans
	msg := cmd()
	_, ok := msg.(LoadScansMsg)
	assert.True(t, ok)
}

func TestScanHistory_View(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*ScanHistory)
		contains []string
	}{
		{
			name: "loading state",
			setup: func(sh *ScanHistory) {
				sh.loading = true
			},
			contains: []string{"Loading scans..."},
		},
		{
			name: "error state",
			setup: func(sh *ScanHistory) {
				sh.loading = false
				sh.errorMsg = "Database connection failed"
			},
			contains: []string{"Error:", "Database connection failed"},
		},
		{
			name: "empty state",
			setup: func(sh *ScanHistory) {
				sh.loading = false
				sh.scans = []ScanHistoryItem{}
			},
			contains: []string{"No previous scans found"},
		},
		{
			name: "with scans",
			setup: func(sh *ScanHistory) {
				sh.loading = false
				sh.scans = createTestScans(2)
			},
			contains: []string{
				"Scan History",
				"Client", "Environment", "Date", "Duration", "Findings", "Status",
				"test-profile", "Completed",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sh := NewScanHistory()
			sh.width = 120
			sh.height = 30
			tt.setup(sh)

			view := sh.View()
			for _, expected := range tt.contains {
				assert.Contains(t, view, expected)
			}
		})
	}
}

func TestScanHistory_PadRight(t *testing.T) {
	sh := NewScanHistory()

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
		result := sh.padRight(tt.str, tt.length)
		assert.Equal(t, tt.expected, result)
		assert.Equal(t, tt.length, len([]rune(result))) // Ensure exact length
	}
}

func TestScanHistory_SetSize(t *testing.T) {
	sh := NewScanHistory()

	sh.SetSize(100, 50)
	assert.Equal(t, 100, sh.width)
	assert.Equal(t, 50, sh.height)
}

func TestScanHistory_SetDatabase(t *testing.T) {
	sh := NewScanHistory()
	db := &database.DB{} // Mock DB

	sh.SetDatabase(db)
	assert.Equal(t, db, sh.db)
}

// Helper function to create test scans.
func createTestScans(count int) []ScanHistoryItem {
	scans := make([]ScanHistoryItem, count)
	for i := 0; i < count; i++ {
		scans[i] = ScanHistoryItem{
			Scan: &database.Scan{
				ID:        int64(i + 1),
				StartedAt: time.Now().Add(time.Duration(-count+i) * time.Hour),
				CompletedAt: sql.NullTime{
					Time:  time.Now().Add(time.Duration(-count+i+1) * time.Hour),
					Valid: true,
				},
				Status: database.ScanStatusCompleted,
				AWSProfile: sql.NullString{
					String: "test-profile",
					Valid:  true,
				},
			},
			FindingCounts: &database.FindingCounts{
				Total:    100 * (i + 1),
				Critical: 10 * (i + 1),
				High:     20 * (i + 1),
				Medium:   30 * (i + 1),
				Low:      40 * (i + 1),
			},
		}
	}
	return scans
}
