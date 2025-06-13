package bubbletea

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Table is a reusable table component using lipgloss.
type Table struct {
	Style   lipgloss.Style
	Headers []string
	Rows    [][]string
	Width   int
}

// Render renders the table.
func (t Table) Render() string {
	if len(t.Headers) == 0 {
		return ""
	}

	// Calculate column widths
	widths := t.calculateColumnWidths()

	// Build rows
	renderedRows := []string{}

	// Render headers
	headerRow := t.renderRow(t.Headers, widths, titleStyle)
	renderedRows = append(renderedRows, headerRow)

	// Render separator
	separator := t.renderSeparator(widths)
	renderedRows = append(renderedRows, separator)

	// Render data rows
	for _, row := range t.Rows {
		dataRow := t.renderRow(row, widths, lipgloss.NewStyle())
		renderedRows = append(renderedRows, dataRow)
	}

	// Join all rows
	return strings.Join(renderedRows, "\n")
}

// calculateColumnWidths calculates the width for each column.
func (t Table) calculateColumnWidths() []int {
	if len(t.Headers) == 0 {
		return []int{}
	}

	// Available width for content (accounting for padding and separators)
	// Each column separator is " │ " (3 chars)
	separatorCount := len(t.Headers) - 1
	separatorWidth := separatorCount * 3
	availableWidth := t.Width - separatorWidth - 4 // 4 for box borders

	// For scanner table, use fixed widths like the original
	if len(t.Headers) == 4 && t.Headers[0] == "Scanner" {
		scannerWidth := 11
		statusWidth := 10
		timeWidth := 8

		// Progress column gets remaining space
		progressWidth := availableWidth - scannerWidth - statusWidth - timeWidth
		if progressWidth < 20 {
			progressWidth = 20
		}

		return []int{scannerWidth, statusWidth, timeWidth, progressWidth}
	}

	// For other tables, distribute evenly
	columnWidth := availableWidth / len(t.Headers)
	widths := make([]int, len(t.Headers))
	for i := range widths {
		widths[i] = columnWidth
	}

	// Give any remaining width to the last column
	remainder := availableWidth - (columnWidth * len(t.Headers))
	if remainder > 0 && len(widths) > 0 {
		widths[len(widths)-1] += remainder
	}

	return widths
}

// renderRow renders a single row with the given widths and style.
func (t Table) renderRow(cells []string, widths []int, style lipgloss.Style) string {
	if len(cells) == 0 {
		return ""
	}

	// Ensure we have the right number of cells
	for len(cells) < len(widths) {
		cells = append(cells, "")
	}

	// Format each cell
	formattedCells := make([]string, len(widths))
	for i, cell := range cells {
		if i < len(widths) {
			formattedCells[i] = t.padOrTruncate(cell, widths[i])
		}
	}

	// Join with separators
	row := strings.Join(formattedCells, " │ ")
	return style.Render(row)
}

// renderSeparator renders a separator line.
func (t Table) renderSeparator(widths []int) string {
	if len(widths) == 0 {
		return ""
	}

	parts := make([]string, len(widths))
	for i, width := range widths {
		parts[i] = strings.Repeat("─", width)
	}

	return grayStyle.Render(strings.Join(parts, "┼"))
}

// padOrTruncate ensures string is exactly the specified width.
func (t Table) padOrTruncate(s string, width int) string {
	// Strip any ANSI codes for accurate length calculation
	visualLen := lipgloss.Width(s)

	switch {
	case visualLen == width:
		return s
	case visualLen < width:
		// Pad with spaces
		return s + strings.Repeat(" ", width-visualLen)
	default:
		// Truncate manually without lipgloss to avoid multiline issues
		if width <= 0 {
			return ""
		}

		// Count visible characters
		result := ""
		count := 0
		inAnsi := false

		for _, ch := range s {
			if ch == '\033' {
				inAnsi = true
				result += string(ch)
				continue
			}

			if inAnsi {
				result += string(ch)
				if ch == 'm' {
					inAnsi = false
				}
				continue
			}

			if count >= width {
				break
			}
			result += string(ch)
			count++
		}

		return result
	}
}
