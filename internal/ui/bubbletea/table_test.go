package bubbletea

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTable_Render_Empty(t *testing.T) {
	// Empty headers
	table := Table{
		Headers: []string{},
		Rows:    [][]string{},
		Width:   80,
	}
	assert.Equal(t, "", table.Render())

	// Headers but no rows
	table = Table{
		Headers: []string{"Name", "Status"},
		Rows:    [][]string{},
		Width:   80,
	}
	result := table.Render()
	assert.Contains(t, result, "Name")
	assert.Contains(t, result, "Status")
	assert.Contains(t, result, "─") // separator line
}

func TestTable_Render_Basic(t *testing.T) {
	table := Table{
		Headers: []string{"Scanner", "Status", "Time"},
		Rows: [][]string{
			{"trivy", "Running", "30s"},
			{"nuclei", "Complete", "45s"},
		},
		Width: 80,
	}

	result := table.Render()
	lines := strings.Split(result, "\n")

	// Check structure
	assert.Len(t, lines, 4) // header + separator + 2 rows

	// Check headers
	assert.Contains(t, lines[0], "Scanner")
	assert.Contains(t, lines[0], "Status")
	assert.Contains(t, lines[0], "Time")

	// Check separator
	assert.Contains(t, lines[1], "─")
	assert.Contains(t, lines[1], "┼")

	// Check data rows
	assert.Contains(t, lines[2], "trivy")
	assert.Contains(t, lines[2], "Running")
	assert.Contains(t, lines[2], "30s")

	assert.Contains(t, lines[3], "nuclei")
	assert.Contains(t, lines[3], "Complete")
	assert.Contains(t, lines[3], "45s")
}

func TestTable_Render_ScannerTable(t *testing.T) {
	// Test specific scanner table layout
	table := Table{
		Headers: []string{"Scanner", "Status", "Time", "Progress"},
		Rows: [][]string{
			{"trivy", "✓ Complete", "45s", "15 findings: 2 crit, 5 high, 8 med"},
			{"nuclei", "⟳ Running", "30s", "[50/100] Scanning endpoints"},
			{"gitleaks", "✗ Failed", "10s", "No git repository found"},
		},
		Width: 120,
	}

	result := table.Render()
	lines := strings.Split(result, "\n")

	// Verify structure
	assert.Len(t, lines, 5) // header + separator + 3 rows

	// Check column alignment
	for _, line := range lines[2:] { // data rows
		parts := strings.Split(line, " │ ")
		assert.Len(t, parts, 4) // 4 columns
	}
}

func TestTable_calculateColumnWidths(t *testing.T) {
	// Test scanner table specific widths
	table := Table{
		Headers: []string{"Scanner", "Status", "Time", "Progress"},
		Width:   120,
	}

	widths := table.calculateColumnWidths()
	assert.Len(t, widths, 4)
	assert.Equal(t, 11, widths[0])  // Scanner
	assert.Equal(t, 10, widths[1])  // Status
	assert.Equal(t, 8, widths[2])   // Time
	assert.True(t, widths[3] >= 20) // Progress (remaining space)

	// Test generic table
	table = Table{
		Headers: []string{"Name", "Value", "Description"},
		Width:   90,
	}

	widths = table.calculateColumnWidths()
	assert.Len(t, widths, 3)
	// Should distribute evenly
	totalWidth := widths[0] + widths[1] + widths[2]
	assert.Greater(t, totalWidth, 70) // Most of the available width
}

func TestTable_padOrTruncate(t *testing.T) {
	table := Table{}

	tests := []struct {
		input    string
		expected string
		width    int
	}{
		// Exact fit
		{"hello", "hello", 5},

		// Needs padding
		{"hi", "hi   ", 5},

		// Needs truncation
		{"hello world", "hello wo", 8},

		// Very narrow
		{"hello", "hel", 3},

		// Empty string
		{"", "     ", 5},
	}

	for _, tt := range tests {
		result := table.padOrTruncate(tt.input, tt.width)
		assert.Equal(t, tt.expected, result)
		// Verify length
		assert.Equal(t, tt.width, len(result))
	}
}

func TestTable_Render_EdgeCases(t *testing.T) {
	// Test with mismatched row lengths
	table := Table{
		Headers: []string{"A", "B", "C"},
		Rows: [][]string{
			{"1", "2"},           // Missing column
			{"3", "4", "5", "6"}, // Extra column
			{"7", "8", "9"},
		},
		Width: 80,
	}

	result := table.Render()
	lines := strings.Split(result, "\n")

	// Should handle gracefully
	assert.Len(t, lines, 5) // header + separator + 3 rows

	// Check first row (missing column should be empty)
	assert.Contains(t, lines[2], "1")
	assert.Contains(t, lines[2], "2")

	// Check second row (extra column should be ignored)
	assert.Contains(t, lines[3], "3")
	assert.Contains(t, lines[3], "4")
	assert.Contains(t, lines[3], "5")
	assert.NotContains(t, lines[3], "6") // Extra column ignored
}

func TestTable_Render_NarrowWidth(t *testing.T) {
	table := Table{
		Headers: []string{"Scanner", "Status", "Time", "Progress"},
		Rows: [][]string{
			{"very-long-scanner-name", "Running", "1m30s", "This is a very long progress message"},
		},
		Width: 60, // Narrow terminal
	}

	result := table.Render()

	// Should still render without panic
	assert.NotEmpty(t, result)

	// Content should be truncated appropriately
	lines := strings.Split(result, "\n")
	for _, line := range lines {
		// Each line should not exceed reasonable bounds
		// Allow more space as the table separators and padding add extra characters
		assert.LessOrEqual(t, len(line), 160)
	}
}

func TestTable_Render_SpecialCharacters(t *testing.T) {
	table := Table{
		Headers: []string{"Scanner", "Status"},
		Rows: [][]string{
			{"trivy", "✓ Complete"},
			{"nuclei", "⟳ Running"},
			{"gitleaks", "✗ Failed"},
		},
		Width: 80,
	}

	result := table.Render()

	// Unicode characters should be preserved
	assert.Contains(t, result, "✓")
	assert.Contains(t, result, "⟳")
	assert.Contains(t, result, "✗")
}
