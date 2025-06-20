package testutil

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// StripANSI removes ANSI escape sequences from a string.
// This is useful for testing views that include color codes.
func StripANSI(str string) string {
	var result strings.Builder
	ansi := false

	for _, r := range str {
		switch {
		case r == '\x1b':
			ansi = true
		case ansi:
			if r == 'm' {
				ansi = false
			}
		default:
			result.WriteRune(r)
		}
	}

	return result.String()
}

// NormalizeWhitespace normalizes whitespace in a string for comparison.
// It trims leading/trailing whitespace and converts multiple spaces to single spaces.
func NormalizeWhitespace(s string) string {
	lines := strings.Split(s, "\n")
	normalized := make([]string, 0, len(lines))

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			// Replace multiple spaces with single space
			parts := strings.Fields(trimmed)
			normalized = append(normalized, strings.Join(parts, " "))
		}
	}

	return strings.Join(normalized, "\n")
}

// CompareViews compares two views after stripping ANSI codes and normalizing whitespace.
func CompareViews(t *testing.T, expected, actual string) {
	t.Helper()

	expectedClean := NormalizeWhitespace(StripANSI(expected))
	actualClean := NormalizeWhitespace(StripANSI(actual))

	if expectedClean != actualClean {
		t.Errorf("Views do not match.\nExpected:\n%s\n\nActual:\n%s", expectedClean, actualClean)
	}
}

// ExtractLines extracts specific lines from a view for comparison.
func ExtractLines(view string, startLine, endLine int) string {
	lines := strings.Split(view, "\n")

	if startLine < 0 {
		startLine = 0
	}
	if endLine > len(lines) {
		endLine = len(lines)
	}
	if startLine >= endLine {
		return ""
	}

	return strings.Join(lines[startLine:endLine], "\n")
}

// CountOccurrences counts how many times a substring appears in a string.
func CountOccurrences(s, substr string) int {
	count := 0
	index := 0

	for {
		idx := strings.Index(s[index:], substr)
		if idx == -1 {
			break
		}
		count++
		index += idx + 1 // Move by 1 to allow overlapping matches
	}

	return count
}

// AssertLineCount asserts that a view has the expected number of lines.
func AssertLineCount(t *testing.T, view string, expected int) {
	t.Helper()

	lines := strings.Split(strings.TrimSpace(view), "\n")
	actual := len(lines)

	if actual != expected {
		t.Errorf("Expected %d lines but got %d.\nView:\n%s", expected, actual, view)
	}
}

// AssertContainsInOrder checks that strings appear in the view in the specified order.
func AssertContainsInOrder(t *testing.T, view string, ordered []string) {
	t.Helper()

	lastIndex := -1
	for _, str := range ordered {
		index := strings.Index(view[lastIndex+1:], str)
		if index == -1 {
			t.Errorf("Expected to find %q after position %d but it wasn't found.\nView:\n%s", str, lastIndex, view)
			return
		}
		lastIndex += index + 1
	}
}

// ExtractTable extracts a table from a view based on header detection.
func ExtractTable(view string, headerStart string) [][]string {
	lines := strings.Split(view, "\n")
	table := [][]string{}
	inTable := false

	for _, line := range lines {
		if strings.Contains(line, headerStart) {
			inTable = true
			continue
		}

		if inTable {
			// Stop at empty line or next section
			if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "[") {
				break
			}

			// Skip divider lines (lines with only dashes)
			trimmed := strings.TrimSpace(line)
			if strings.Count(trimmed, "-") == len(trimmed)-strings.Count(trimmed, " ") {
				continue
			}

			// Parse table row
			fields := strings.Fields(trimmed)
			if len(fields) > 0 {
				table = append(table, fields)
			}
		}
	}

	return table
}

// AssertTableRowCount asserts that a table has the expected number of rows.
func AssertTableRowCount(t *testing.T, view string, headerStart string, expected int) {
	t.Helper()

	table := ExtractTable(view, headerStart)
	actual := len(table)

	if actual != expected {
		t.Errorf("Expected table to have %d rows but got %d", expected, actual)
	}
}

// GetVisibleText returns only visible text (non-whitespace) from a view.
func GetVisibleText(view string) string {
	lines := strings.Split(view, "\n")
	visible := []string{}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			visible = append(visible, trimmed)
		}
	}

	return strings.Join(visible, "\n")
}

// AssertNoErrors checks that a view doesn't contain error indicators.
func AssertNoErrors(t *testing.T, view string) {
	t.Helper()

	errorIndicators := []string{
		"Error:",
		"error:",
		"ERROR:",
		"Failed",
		"failed",
		"FAILED",
		"panic:",
		"PANIC:",
	}

	for _, indicator := range errorIndicators {
		if strings.Contains(view, indicator) {
			t.Errorf("View contains error indicator %q:\n%s", indicator, view)
		}
	}
}

// CaptureViewport extracts the visible viewport from a view based on dimensions.
func CaptureViewport(view string, width, height int) string {
	lines := strings.Split(view, "\n")
	viewport := []string{}

	for i, line := range lines {
		if i >= height {
			break
		}

		// Truncate line to viewport width
		runes := []rune(line)
		if len(runes) > width {
			line = string(runes[:width])
		}

		viewport = append(viewport, line)
	}

	return strings.Join(viewport, "\n")
}

// AssertViewportContains checks that content appears within the viewport dimensions.
func AssertViewportContains(t *testing.T, view string, width, height int, expected string) {
	t.Helper()

	viewport := CaptureViewport(view, width, height)

	assert.Contains(t, viewport, expected,
		"Expected viewport (%dx%d) to contain %q", width, height, expected)
}

// RemoveBoxDrawing removes box drawing characters for cleaner comparison.
func RemoveBoxDrawing(s string) string {
	boxChars := "─│┌┐└┘├┤┬┴┼╭╮╰╯║═╔╗╚╝╠╣╦╩╬"

	var result strings.Builder
	for _, r := range s {
		if !strings.ContainsRune(boxChars, r) {
			result.WriteRune(r)
		}
	}

	return result.String()
}

// IsValidJSON checks if a string contains valid JSON.
func IsValidJSON(t *testing.T, jsonStr string) {
	t.Helper()

	// Simple check for JSON structure
	jsonStr = strings.TrimSpace(jsonStr)
	if !strings.HasPrefix(jsonStr, "{") && !strings.HasPrefix(jsonStr, "[") {
		t.Errorf("String does not appear to be valid JSON: %s", jsonStr)
	}

	// Check for balanced braces
	braceCount := 0
	bracketCount := 0
	inString := false
	escaped := false

	for _, r := range jsonStr {
		if escaped {
			escaped = false
			continue
		}

		switch r {
		case '\\':
			escaped = true
		case '"':
			inString = !inString
		case '{':
			if !inString {
				braceCount++
			}
		case '}':
			if !inString {
				braceCount--
			}
		case '[':
			if !inString {
				bracketCount++
			}
		case ']':
			if !inString {
				bracketCount--
			}
		}
	}

	if braceCount != 0 {
		t.Errorf("Unbalanced braces in JSON: %d", braceCount)
	}
	if bracketCount != 0 {
		t.Errorf("Unbalanced brackets in JSON: %d", bracketCount)
	}
}
