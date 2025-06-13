package bubbletea

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// Style definitions using lipgloss.
var (
	// Base styles.
	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("86")) // Cyan

	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("86"))

		// Severity colors.
	criticalStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("196")) // Red
	highStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("208")) // Orange
	mediumStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("226")) // Yellow
	lowStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("46"))  // Green
	// infoStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("245")) // Gray - unused for now.

	// Status styles.
	successIcon  = lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Render("✓")
	failIcon     = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("✗")
	runningIcon  = lipgloss.NewStyle().Foreground(lipgloss.Color("226")).Render("⟳")
	pendingIcon  = lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("○")
	startingIcon = lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Render("🚀")
	skippedIcon  = lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("⏭")

	// Text styles.
	boldStyle  = lipgloss.NewStyle().Bold(true)
	grayStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	errorStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
)

// View renders the entire UI.
func (m Model) View() string {
	if m.width == 0 {
		return "Initializing..."
	}

	sections := []string{
		m.renderHeader(),
		m.renderRepositories(),
		m.renderScanners(),
		m.renderSummary(),
	}

	// Only show errors if present
	if m.errors.Len() > 0 {
		sections = append(sections, m.renderErrors())
	}

	// Show final summary if scan complete
	if m.showFinalSummary {
		sections = append(sections, m.renderFinalSummary())
	}

	// Filter out empty sections
	nonEmptySections := []string{}
	for _, section := range sections {
		if section != "" {
			nonEmptySections = append(nonEmptySections, section)
		}
	}

	return lipgloss.JoinVertical(lipgloss.Left, nonEmptySections...)
}

// renderHeader renders the header box.
func (m Model) renderHeader() string {
	elapsed := time.Since(m.startTime).Round(time.Second)

	lines := []string{
		fmt.Sprintf("Output: %s", m.outputDir),
		fmt.Sprintf("Client: %s | Environment: %s | Elapsed: %s",
			m.client, m.environment, elapsed),
	}
	
	// Add navigation hint if there's scrollable content
	hasScrollableContent := (m.errors.Len() > m.infoMaxHeight) || 
		(m.showFinalSummary && len(m.finalMessage) > m.infoMaxHeight)
	
	if hasScrollableContent {
		lines = append(lines, grayStyle.Render("Navigation: ↑↓/jk = scroll, g/G = top/bottom, PgUp/PgDn = page, q = quit"))
	} else {
		// Always show quit hint
		lines = append(lines, grayStyle.Render("Press q or Ctrl+C to quit"))
	}

	return m.renderBox("Prismatic Security Scanner", lines)
}

// renderRepositories renders the repository status box.
func (m Model) renderRepositories() string {
	if len(m.repos) == 0 {
		return ""
	}

	lines := []string{}
	for _, repo := range m.repos {
		icon := m.getRepoIcon(repo.Status)
		status := ""

		switch repo.Status {
		case RepoStatusCloning:
			status = "Cloning..."
		case RepoStatusReady:
			status = "Ready"
		case RepoStatusFailed:
			if repo.Error != "" {
				status = fmt.Sprintf("Failed: %s", repo.Error)
			} else {
				status = "Failed"
			}
		case RepoStatusPending:
			status = "Pending"
		}

		line := fmt.Sprintf("%s %s: %s", icon, repo.Name, status)
		lines = append(lines, line)
	}

	return m.renderBox("Repository Preparation", lines)
}

// renderScanners renders the scanner status box.
func (m Model) renderScanners() string {
	if len(m.scanners) == 0 {
		return ""
	}

	// Create table
	table := m.buildScannerTable()
	return m.renderBox("Scanner Status", []string{table})
}

// buildScannerTable builds the scanner status table.
func (m Model) buildScannerTable() string {
	headers := []string{"Scanner", "Status", "Time", "Progress"}
	rows := [][]string{}

	for _, scanner := range m.scanners {
		rows = append(rows, []string{
			scanner.Name,
			m.formatStatus(scanner.Status),
			m.formatDuration(scanner.Duration),
			m.formatProgress(scanner),
		})
	}

	table := Table{
		Headers: headers,
		Rows:    rows,
		Width:   m.getBoxWidth(),
	}

	return table.Render()
}

// renderSummary renders the findings summary box.
func (m Model) renderSummary() string {
	total := 0
	bySeverity := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}

	for _, scanner := range m.scanners {
		if scanner.Findings.BySeverity != nil {
			for sev, count := range scanner.Findings.BySeverity {
				bySeverity[sev] += count
				total += count
			}
		}
	}

	// Build colored summary
	parts := []string{
		boldStyle.Render(fmt.Sprintf("Total: %d", total)),
	}

	// Add severity counts with appropriate colors
	if bySeverity["critical"] > 0 {
		parts = append(parts, criticalStyle.Render(fmt.Sprintf("Critical: %d", bySeverity["critical"])))
	}
	if bySeverity["high"] > 0 {
		parts = append(parts, highStyle.Render(fmt.Sprintf("High: %d", bySeverity["high"])))
	}
	if bySeverity["medium"] > 0 {
		parts = append(parts, mediumStyle.Render(fmt.Sprintf("Medium: %d", bySeverity["medium"])))
	}
	if bySeverity["low"] > 0 {
		parts = append(parts, lowStyle.Render(fmt.Sprintf("Low: %d", bySeverity["low"])))
	}

	summary := strings.Join(parts, "  ")
	return m.renderBox("Finding Summary", []string{summary})
}

// renderErrors renders the error box.
func (m Model) renderErrors() string {
	errors := m.errors.Items()
	lines := make([]string, len(errors))
	for i, err := range errors {
		lines[i] = errorStyle.Render(fmt.Sprintf("[%s] %s", err.Scanner, err.Message))
	}
	return m.renderScrollableBox("Recent Errors", lines)
}

// renderFinalSummary renders the final summary box.
func (m Model) renderFinalSummary() string {
	return m.renderScrollableBox("✨ Scan Complete!", m.finalMessage)
}

// renderBox renders a box with title and content.
func (m Model) renderBox(title string, lines []string) string {
	width := m.getBoxWidth()

	// Join lines with newlines
	content := strings.Join(lines, "\n")

	// Apply box style with title
	return boxStyle.
		Width(width).
		Render(titleStyle.Render(title) + "\n\n" + content)
}

// renderScrollableBox renders a box with scrollable content.
func (m Model) renderScrollableBox(title string, lines []string) string {
	width := m.getBoxWidth()
	
	// Apply scrolling
	totalLines := len(lines)
	if totalLines == 0 {
		return m.renderBox(title, []string{"No items to display"})
	}
	
	// Adjust scroll offset to valid range
	maxOffset := totalLines - m.infoMaxHeight
	if maxOffset < 0 {
		maxOffset = 0
	}
	scrollOffset := m.infoScrollOffset
	if scrollOffset > maxOffset {
		scrollOffset = maxOffset
	}
	if scrollOffset < 0 {
		scrollOffset = 0
	}
	
	// Get visible lines
	visibleLines := lines
	showScrollIndicators := false
	if totalLines > m.infoMaxHeight {
		showScrollIndicators = true
		endIdx := scrollOffset + m.infoMaxHeight
		if endIdx > totalLines {
			endIdx = totalLines
		}
		visibleLines = lines[scrollOffset:endIdx]
	}
	
	// Build content with scroll indicators
	var contentParts []string
	
	// Add title with scroll position indicator if needed
	titleText := title
	if showScrollIndicators {
		titleText = fmt.Sprintf("%s (%d-%d of %d)", 
			title, 
			scrollOffset+1, 
			scrollOffset+len(visibleLines), 
			totalLines)
	}
	
	// Add top scroll indicator
	if showScrollIndicators && scrollOffset > 0 {
		contentParts = append(contentParts, grayStyle.Render("▲ More above (↑/k to scroll)"))
	}
	
	// Add visible lines
	contentParts = append(contentParts, strings.Join(visibleLines, "\n"))
	
	// Add bottom scroll indicator
	if showScrollIndicators && scrollOffset < maxOffset {
		contentParts = append(contentParts, grayStyle.Render("▼ More below (↓/j to scroll)"))
	}
	
	// Join all parts
	content := strings.Join(contentParts, "\n")
	
	// Apply box style with title
	return boxStyle.
		Width(width).
		Render(titleStyle.Render(titleText) + "\n\n" + content)
}

// getBoxWidth returns the appropriate box width.
func (m Model) getBoxWidth() int {
	maxWidth := 120
	if m.width < maxWidth {
		return m.width - 2 // Account for margins
	}
	return maxWidth
}

// formatStatus formats scanner status with icon.
func (m Model) formatStatus(status ScannerStatus) string {
	icon := m.getScannerIcon(status)
	text := m.getScannerStatusText(status)
	return fmt.Sprintf("%s %s", icon, text)
}

// formatDuration formats a duration for display.
func (m Model) formatDuration(d time.Duration) string {
	if d == 0 {
		return "-"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	minutes := int(d.Minutes())
	seconds := int(d.Seconds()) % 60
	return fmt.Sprintf("%dm%ds", minutes, seconds)
}

// formatProgress formats scanner progress.
func (m Model) formatProgress(scanner ScannerState) string {
	if scanner.Status == ScannerStatusFailed && scanner.Message != "" {
		return scanner.Message
	}

	if scanner.Status == ScannerStatusSuccess {
		if scanner.Findings.Total == 0 {
			return "No findings"
		}
		// Build detailed severity summary
		parts := []string{}
		if c := scanner.Findings.BySeverity["critical"]; c > 0 {
			parts = append(parts, fmt.Sprintf("%d crit", c))
		}
		if h := scanner.Findings.BySeverity["high"]; h > 0 {
			parts = append(parts, fmt.Sprintf("%d high", h))
		}
		if m := scanner.Findings.BySeverity["medium"]; m > 0 {
			parts = append(parts, fmt.Sprintf("%d med", m))
		}
		if l := scanner.Findings.BySeverity["low"]; l > 0 {
			parts = append(parts, fmt.Sprintf("%d low", l))
		}
		return fmt.Sprintf("%d findings: %s", scanner.Findings.Total, strings.Join(parts, ", "))
	}

	if scanner.Progress.Total > 0 {
		if scanner.Message != "" {
			return fmt.Sprintf("[%d/%d] %s", scanner.Progress.Current, scanner.Progress.Total, scanner.Message)
		}
		return fmt.Sprintf("Progress: %d/%d", scanner.Progress.Current, scanner.Progress.Total)
	}

	if scanner.Message != "" {
		return scanner.Message
	}

	return "Initializing..."
}

// getRepoIcon returns the icon for a repository status.
func (m Model) getRepoIcon(status RepoStatus) string {
	switch status {
	case RepoStatusPending:
		return pendingIcon
	case RepoStatusCloning:
		return runningIcon
	case RepoStatusReady:
		return successIcon
	case RepoStatusFailed:
		return failIcon
	default:
		return "?"
	}
}

// getScannerIcon returns the icon for a scanner status.
func (m Model) getScannerIcon(status ScannerStatus) string {
	switch status {
	case ScannerStatusPending:
		return pendingIcon
	case ScannerStatusStarting:
		return startingIcon
	case ScannerStatusRunning:
		return runningIcon
	case ScannerStatusSuccess:
		return successIcon
	case ScannerStatusFailed:
		return failIcon
	case ScannerStatusSkipped:
		return skippedIcon
	default:
		return "?"
	}
}

// getScannerStatusText returns the text for a scanner status.
func (m Model) getScannerStatusText(status ScannerStatus) string {
	switch status {
	case ScannerStatusPending:
		return "Pending"
	case ScannerStatusStarting:
		return "Starting"
	case ScannerStatusRunning:
		return "Running"
	case ScannerStatusSuccess:
		return "Complete"
	case ScannerStatusFailed:
		return "Failed"
	case ScannerStatusSkipped:
		return "Skipped"
	default:
		return "Unknown"
	}
}
