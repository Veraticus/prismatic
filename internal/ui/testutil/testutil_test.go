package testutil

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/joshsymonds/prismatic/internal/database"
)

func TestStripANSI(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no ansi codes",
			input:    "Hello World",
			expected: "Hello World",
		},
		{
			name:     "with color codes",
			input:    "\x1b[31mRed Text\x1b[0m",
			expected: "Red Text",
		},
		{
			name:     "multiple codes",
			input:    "\x1b[1m\x1b[32mBold Green\x1b[0m Normal \x1b[4mUnderline\x1b[0m",
			expected: "Bold Green Normal Underline",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := StripANSI(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeWhitespace(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "extra spaces",
			input:    "Hello    World",
			expected: "Hello World",
		},
		{
			name:     "leading/trailing spaces",
			input:    "  Hello World  ",
			expected: "Hello World",
		},
		{
			name:     "multiple lines",
			input:    "Line 1\n  Line 2  \n\nLine 3",
			expected: "Line 1\nLine 2\nLine 3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeWhitespace(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCountOccurrences(t *testing.T) {
	tests := []struct {
		name     string
		str      string
		substr   string
		expected int
	}{
		{"single occurrence", "Hello World", "World", 1},
		{"multiple occurrences", "foo bar foo baz foo", "foo", 3},
		{"no occurrences", "Hello World", "xyz", 0},
		{"overlapping", "aaaa", "aa", 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count := CountOccurrences(tt.str, tt.substr)
			assert.Equal(t, tt.expected, count)
		})
	}
}

func TestExtractLines(t *testing.T) {
	view := "Line 1\nLine 2\nLine 3\nLine 4\nLine 5"

	tests := []struct {
		name     string
		expected string
		start    int
		end      int
	}{
		{"first two lines", "Line 1\nLine 2", 0, 2},
		{"middle lines", "Line 3\nLine 4", 2, 4},
		{"out of bounds", view, -1, 10},
		{"invalid range", "", 5, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractLines(view, tt.start, tt.end)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAssertContainsInOrder(t *testing.T) {
	view := "Header\nFirst Item\nSecond Item\nThird Item\nFooter"

	// Should pass
	AssertContainsInOrder(t, view, []string{"Header", "First", "Third"})

	// Test that it fails when order is wrong
	mockT := &testing.T{}
	AssertContainsInOrder(mockT, view, []string{"Third", "First"})
	assert.True(t, mockT.Failed())
}

func TestExtractTable(t *testing.T) {
	view := `
Title

Name    Status    Count
----    ------    -----
Item1   Active    10
Item2   Inactive  5
Item3   Active    15

Footer text
`

	table := ExtractTable(view, "Name")

	assert.Len(t, table, 3)
	assert.Equal(t, []string{"Item1", "Active", "10"}, table[0])
	assert.Equal(t, []string{"Item2", "Inactive", "5"}, table[1])
	assert.Equal(t, []string{"Item3", "Active", "15"}, table[2])
}

func TestRemoveBoxDrawing(t *testing.T) {
	input := "┌─────┐\n│Hello│\n└─────┘"
	expected := "\nHello\n"

	result := RemoveBoxDrawing(input)
	assert.Equal(t, expected, result)
}

func TestCreateTestData(t *testing.T) {
	db := CreateMemoryDB(t)

	// Test scan creation
	scan := CreateTestScan(t, db, "test-profile", database.ScanStatusRunning)
	assert.NotZero(t, scan.ID)
	assert.Equal(t, "test-profile", scan.AWSProfile.String)
	assert.Equal(t, database.ScanStatusRunning, scan.Status)

	// Test findings creation
	findings := CreateTestFindings(t, db, scan.ID, 5)
	assert.Len(t, findings, 5)

	// Verify findings have different severities
	severities := make(map[database.Severity]bool)
	for _, f := range findings {
		severities[f.Severity] = true
	}
	assert.Greater(t, len(severities), 1)

	// Test scan history creation
	history := CreateTestScanHistory(t, db, 3)
	assert.Len(t, history, 3)

	// Verify each scan has findings
	for _, item := range history {
		assert.NotNil(t, item.FindingCounts)
		assert.Greater(t, item.FindingCounts.Total, 0)
	}
}

func TestCreateTestModelsFindings(t *testing.T) {
	findings := CreateTestModelsFindings(10)

	assert.Len(t, findings, 10)

	// Check that findings have unique IDs
	ids := make(map[string]bool)
	for _, f := range findings {
		assert.NotEmpty(t, f.ID)
		assert.False(t, ids[f.ID], "Duplicate ID found: %s", f.ID)
		ids[f.ID] = true
	}

	// Check that findings have various severities
	severities := make(map[string]bool)
	for _, f := range findings {
		severities[f.Severity] = true
	}
	assert.Greater(t, len(severities), 1)
}

func TestAssertViewContains(t *testing.T) {
	view := "Header\nContent Line 1\nContent Line 2\nFooter"

	// Should pass
	AssertViewContains(t, view, []string{"Header", "Content", "Footer"})

	// Test that it fails when content is missing
	mockT := &testing.T{}
	AssertViewContains(mockT, view, []string{"Missing"})
	assert.True(t, mockT.Failed())
}

func TestCaptureViewport(t *testing.T) {
	view := strings.Repeat("A", 100) + "\n" +
		strings.Repeat("B", 100) + "\n" +
		strings.Repeat("C", 100)

	viewport := CaptureViewport(view, 50, 2)

	lines := strings.Split(viewport, "\n")
	assert.Len(t, lines, 2)
	assert.Equal(t, strings.Repeat("A", 50), lines[0])
	assert.Equal(t, strings.Repeat("B", 50), lines[1])
}

func TestIsValidJSON(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		shouldErr bool
	}{
		{"valid object", `{"key": "value"}`, false},
		{"valid array", `[1, 2, 3]`, false},
		{"invalid - not json", `not json`, true},
		{"unbalanced braces", `{"key": "value"`, true},
		{"unbalanced brackets", `[1, 2, 3`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockT := &testing.T{}
			IsValidJSON(mockT, tt.input)

			if tt.shouldErr {
				assert.True(t, mockT.Failed(), "Expected JSON validation to fail")
			} else {
				assert.False(t, mockT.Failed(), "Expected JSON validation to pass")
			}
		})
	}
}

func TestMockMessages(t *testing.T) {
	messages := CreateMockMessages()

	// Verify all expected message types exist
	expectedTypes := []string{
		"scanner_tick",
		"scanner_status",
		"repo_status",
		"scanner_error",
		"finding",
		"scan_complete",
		"load_scans",
		"load_findings",
	}

	for _, msgType := range expectedTypes {
		_, exists := messages[msgType]
		assert.True(t, exists, "Missing message type: %s", msgType)
	}
}

func TestCreateTestScannerStatus(t *testing.T) {
	status := CreateTestScannerStatus("trivy", "running")

	assert.Equal(t, "trivy", status.Scanner)
	assert.Equal(t, "running", status.Status)
	assert.NotZero(t, status.StartTime)
	assert.Equal(t, 50, status.TotalFindings)
	assert.NotEmpty(t, status.FindingCounts)
}

func TestDatabaseContext(t *testing.T) {
	db := CreateMemoryDB(t)

	// Create a context for database operations
	ctx := context.Background()
	require.NotNil(t, ctx)

	// Test that we can use the context
	scan := &database.Scan{
		Status:   database.ScanStatusRunning,
		Scanners: database.ScannerTrivy,
	}

	scanID, err := db.CreateScan(ctx, scan)
	require.NoError(t, err)
	assert.NotZero(t, scanID)
}
