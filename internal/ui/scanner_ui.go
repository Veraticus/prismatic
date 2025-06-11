// Package ui provides terminal user interface components for the scanner.
package ui

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/term"

	"github.com/joshsymonds/prismatic/internal/models"
)

// ScannerUI manages the terminal UI for scanner operations.
type ScannerUI struct {
	config          Config
	repoStatuses    map[string]RepoStatus
	scannerStatuses map[string]*models.ScannerStatus
	stopChan        chan bool
	renderTicker    *time.Ticker
	errorMessages   []string
	boxWidth        int // Fixed width for all boxes
	mu              sync.Mutex
	stopped         atomic.Bool
	stopOnce        sync.Once
}

// Config holds configuration for the scanner UI.
type Config struct {
	StartTime   time.Time
	OutputDir   string
	ClientName  string
	Environment string
}

// RepoStatus represents the status of a repository.
type RepoStatus struct {
	Name      string
	URL       string
	Status    string // "pending", "cloning", "complete", "failed"
	LocalPath string
	Error     string
}

// Repository status constants.
const (
	RepoStatusPending  = "pending"
	RepoStatusCloning  = "cloning"
	RepoStatusComplete = "complete"
	RepoStatusFailed   = "failed"
)

// ANSI color codes.
const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorGray    = "\033[90m"
	colorBold    = "\033[1m"
)

// NewScannerUI creates a new scanner UI instance.
func NewScannerUI(config Config) *ScannerUI {
	ui := &ScannerUI{
		config:          config,
		repoStatuses:    make(map[string]RepoStatus),
		scannerStatuses: make(map[string]*models.ScannerStatus),
		errorMessages:   []string{},
		stopChan:        make(chan bool),
	}

	// Set fixed box width based on terminal size
	ui.updateBoxWidth()

	return ui
}

// Start begins the UI rendering loop.
func (ui *ScannerUI) Start() {
	// Clear screen and hide cursor
	_, _ = os.Stdout.WriteString("\033[2J\033[H\033[?25l")

	// Start render ticker
	ui.renderTicker = time.NewTicker(100 * time.Millisecond)

	go func() {
		ui.render()
		for {
			select {
			case <-ui.renderTicker.C:
				ui.render()
			case <-ui.stopChan:
				ui.renderTicker.Stop()
				return
			}
		}
	}()
}

// Stop stops the UI rendering and restores terminal.
func (ui *ScannerUI) Stop() {
	ui.stopOnce.Do(func() {
		ui.stopped.Store(true)
		close(ui.stopChan)
		// Show cursor for backward compatibility with tests
		_, _ = os.Stdout.WriteString("\033[?25h")
	})
}

// UpdateRepository updates the status of a repository.
func (ui *ScannerUI) UpdateRepository(name, status, localPath string, err error) {
	ui.mu.Lock()
	defer ui.mu.Unlock()

	repo, ok := ui.repoStatuses[name]
	if !ok {
		// Create new repo status if it doesn't exist
		repo = RepoStatus{
			Name:   name,
			Status: status,
		}
	} else {
		repo.Status = status
	}

	repo.LocalPath = localPath
	if err != nil {
		repo.Error = err.Error()
		repo.Status = RepoStatusFailed
	}
	ui.repoStatuses[name] = repo
}

// UpdateScanner updates scanner status.
func (ui *ScannerUI) UpdateScanner(status *models.ScannerStatus) {
	ui.mu.Lock()
	defer ui.mu.Unlock()

	// Update elapsed time for running scanners
	if status.Status == models.StatusRunning || status.Status == models.StatusStarting {
		status.UpdateElapsedTime()
	}

	ui.scannerStatuses[status.Scanner] = status
}

// AddError adds an error message to display.
func (ui *ScannerUI) AddError(scanner, message string) {
	ui.mu.Lock()
	defer ui.mu.Unlock()

	ui.errorMessages = append(ui.errorMessages, fmt.Sprintf("[%s] %s", scanner, message))
	// Keep only last 5 errors
	if len(ui.errorMessages) > 5 {
		ui.errorMessages = ui.errorMessages[len(ui.errorMessages)-5:]
	}
}

// IsStopped returns true if the UI has been stopped.
func (ui *ScannerUI) IsStopped() bool {
	return ui.stopped.Load()
}

// render draws the entire UI.
func (ui *ScannerUI) render() {
	ui.mu.Lock()
	defer ui.mu.Unlock()

	// Update box width in case terminal was resized
	ui.updateBoxWidth()

	// Update elapsed time for all running scanners
	for _, status := range ui.scannerStatuses {
		if status.Status == models.StatusRunning || status.Status == models.StatusStarting {
			status.UpdateElapsedTime()
		}
	}

	// Move cursor to top
	_, _ = os.Stdout.WriteString("\033[H")

	// Render header
	ui.renderHeader()

	// Render repository status
	ui.renderRepositories()

	// Render scanner status
	ui.renderScanners()

	// Render findings summary
	ui.renderSummary()

	// Render errors if any
	if len(ui.errorMessages) > 0 {
		ui.renderErrors()
	}
}

// RenderFinalState renders the UI one last time with the given summary and keeps it visible.
func (ui *ScannerUI) RenderFinalState(summaryLines []string) {
	ui.mu.Lock()
	defer ui.mu.Unlock()

	// Stop the ticker but don't clear the UI
	if ui.renderTicker != nil {
		ui.renderTicker.Stop()
	}

	// Update box width in case terminal was resized
	ui.updateBoxWidth()

	// Move cursor to top
	_, _ = os.Stdout.WriteString("\033[H")

	// Render header
	ui.renderHeader()

	// Render repository status
	ui.renderRepositories()

	// Render scanner status
	ui.renderScanners()

	// Render findings summary
	ui.renderSummary()

	// Render errors if any
	if len(ui.errorMessages) > 0 {
		ui.renderErrors()
	}

	// Render the final summary box
	if len(summaryLines) > 0 {
		_, _ = os.Stdout.WriteString(ui.drawBox("✨ Scan Complete!", summaryLines))
	}

	// Move cursor to bottom and show it
	_, _ = fmt.Fprintf(os.Stdout, "\033[%d;1H", ui.getTermHeight())
	_, _ = os.Stdout.WriteString("\033[?25h")
}

func (ui *ScannerUI) renderHeader() {
	elapsed := time.Since(ui.config.StartTime).Round(time.Second)

	lines := []string{
		fmt.Sprintf("Output: %s", ui.config.OutputDir),
		fmt.Sprintf("Client: %s | Environment: %s | Elapsed: %s",
			ui.config.ClientName, ui.config.Environment, elapsed),
	}

	_, _ = os.Stdout.WriteString(ui.drawBox("Prismatic Security Scanner", lines))
}

func (ui *ScannerUI) renderRepositories() {
	if len(ui.repoStatuses) == 0 {
		return
	}

	lines := []string{}
	for _, name := range ui.getSortedRepoNames() {
		repo := ui.repoStatuses[name]
		icon := ui.getRepoIcon(repo.Status)
		status := ""

		switch repo.Status {
		case RepoStatusCloning:
			status = "Cloning..."
		case RepoStatusComplete:
			status = "Ready"
		case RepoStatusFailed:
			status = fmt.Sprintf("Failed: %s", repo.Error)
		}

		// Match the expected test output format exactly
		// Format: icon + space + name + padding + status
		// The visual position of "Ready" should be at column 28 (0-indexed)
		iconAndSpace := fmt.Sprintf("%s ", icon)
		// Calculate padding: we want "Ready" to start at visual position 28
		currentPos := ui.visualLength(iconAndSpace) + len(name)
		paddingNeeded := 28 - currentPos
		if paddingNeeded < 1 {
			paddingNeeded = 1
		}
		line := fmt.Sprintf("%s%s%s%s", iconAndSpace, name, strings.Repeat(" ", paddingNeeded), status)
		lines = append(lines, line)
	}

	_, _ = os.Stdout.WriteString(ui.drawBox("Repository Preparation", lines))
}

func (ui *ScannerUI) renderScanners() {
	// Only show scanners that have been registered
	activeScanners := []string{}
	for name := range ui.scannerStatuses {
		activeScanners = append(activeScanners, name)
	}

	// Sort for consistent display
	for i := range activeScanners {
		for j := i + 1; j < len(activeScanners); j++ {
			if activeScanners[i] > activeScanners[j] {
				activeScanners[i], activeScanners[j] = activeScanners[j], activeScanners[i]
			}
		}
	}

	if len(activeScanners) == 0 {
		return // No scanners to display
	}

	// Build the table
	table := ui.buildScannerTable(activeScanners)
	_, _ = os.Stdout.WriteString(ui.drawBox("Scanner Status", table))
}

// buildScannerTable builds the scanner status table.
func (ui *ScannerUI) buildScannerTable(scanners []string) []string {
	// Calculate available width for the table content
	contentWidth := ui.boxWidth - 4 // Account for box borders "│ " and " │"

	// Define minimum column widths
	scannerWidth := 11
	statusWidth := 10
	timeWidth := 8
	minProgressWidth := 20

	// Calculate the exact column separators in the header format:
	// "Scanner     │ Status     │ Time     │ Progress..."
	// The separators are: " │ " which is 3 chars each, times 3 = 9 total
	separatorOverhead := 9

	// Calculate progress width to fill remaining space
	progressWidth := contentWidth - scannerWidth - statusWidth - timeWidth - separatorOverhead

	// Ensure minimum progress width
	if progressWidth < minProgressWidth {
		progressWidth = minProgressWidth
	}

	// Build header - ensure exact spacing
	// The format is: "Scanner     │ Status     │ Time     │ Progress..."
	// Note the spacing: field + space + "│" + space
	header := fmt.Sprintf("%s%-*s │ %-*s │ %-*s │ %-*s%s",
		colorBold,
		scannerWidth, "Scanner",
		statusWidth, "Status",
		timeWidth, "Time",
		progressWidth, "Progress",
		colorReset)

	// Build separator line matching the exact header format
	// The separator should match: "───────────┼────────────┼──────────┼────────..."
	// Format is: dashes matching column width, then ┼ separator between columns
	separator := fmt.Sprintf("%s%s┼%s┼%s┼%s%s",
		colorGray,
		strings.Repeat("─", scannerWidth),    // 11 dashes
		strings.Repeat("─", statusWidth+2),   // 12 dashes
		strings.Repeat("─", timeWidth+2),     // 10 dashes
		strings.Repeat("─", progressWidth+2), // Rest of the line
		colorReset)

	lines := []string{header, separator}

	// Add data rows
	for _, name := range scanners {
		status := ui.scannerStatuses[name]
		if status == nil {
			continue
		}

		row := ui.formatScannerRow(name, status, scannerWidth, statusWidth, timeWidth, progressWidth)
		lines = append(lines, row)
	}

	return lines
}

// formatScannerRow formats a single scanner row.
func (ui *ScannerUI) formatScannerRow(name string, status *models.ScannerStatus, scannerWidth, statusWidth, timeWidth, progressWidth int) string {
	icon := ui.getScannerIcon(status.Status)
	statusText := ui.getScannerStatusText(status.Status)
	timeStr := "-"
	if status.ElapsedTime != "" {
		timeStr = status.ElapsedTime
	}
	progress := ui.getScannerProgress(status)

	// Determine row color
	rowColor := ""
	switch status.Status {
	case models.StatusFailed:
		rowColor = colorRed
	case models.StatusSuccess:
		if status.TotalFindings > 0 && status.FindingCounts["critical"] > 0 {
			rowColor = colorRed
		} else if status.TotalFindings > 0 && status.FindingCounts["high"] > 0 {
			rowColor = colorYellow
		}
	}

	// Format each cell with proper padding
	scannerCell := ui.padOrTruncate(name, scannerWidth)
	statusCell := fmt.Sprintf("%s %s", icon, ui.padOrTruncate(statusText, statusWidth-2))
	timeCell := ui.padOrTruncate(timeStr, timeWidth)
	progressCell := ui.padOrTruncate(progress, progressWidth)

	return fmt.Sprintf("%s%s%s │ %s │ %s │ %s",
		rowColor, scannerCell, colorReset,
		statusCell, timeCell, progressCell)
}

// padOrTruncate ensures string is exactly the specified width.
func (ui *ScannerUI) padOrTruncate(s string, width int) string {
	visualLen := ui.visualLength(s)
	switch {
	case visualLen == width:
		return s
	case visualLen < width:
		// Pad with spaces
		return s + strings.Repeat(" ", width-visualLen)
	default:
		// Truncate
		return ui.smartTruncate(s, width)
	}
}

func (ui *ScannerUI) renderSummary() {
	total := 0
	bySeverity := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}

	for _, status := range ui.scannerStatuses {
		if status.FindingCounts != nil {
			for sev, count := range status.FindingCounts {
				bySeverity[sev] += count
				total += count
			}
		}
	}

	// Build colored summary
	parts := []string{
		fmt.Sprintf("%sTotal: %d%s", colorBold, total, colorReset),
	}

	// Add severity counts with appropriate colors
	if bySeverity["critical"] > 0 {
		parts = append(parts, fmt.Sprintf("%sCritical: %d%s", colorRed, bySeverity["critical"], colorReset))
	}
	if bySeverity["high"] > 0 {
		parts = append(parts, fmt.Sprintf("%sHigh: %d%s", colorYellow, bySeverity["high"], colorReset))
	}
	if bySeverity["medium"] > 0 {
		parts = append(parts, fmt.Sprintf("%sMedium: %d%s", colorBlue, bySeverity["medium"], colorReset))
	}
	if bySeverity["low"] > 0 {
		parts = append(parts, fmt.Sprintf("%sLow: %d%s", colorGreen, bySeverity["low"], colorReset))
	}

	summary := strings.Join(parts, "  ")
	_, _ = os.Stdout.WriteString(ui.drawBox("Finding Summary", []string{summary}))
}

func (ui *ScannerUI) renderErrors() {
	// Color errors in red
	coloredErrors := make([]string, len(ui.errorMessages))
	for i, err := range ui.errorMessages {
		coloredErrors[i] = colorRed + err + colorReset
	}
	_, _ = os.Stdout.WriteString(ui.drawBox("Recent Errors", coloredErrors))
}

// updateBoxWidth calculates the appropriate fixed width for all boxes.
func (ui *ScannerUI) updateBoxWidth() {
	width := ui.getTermWidth()
	if width > 120 {
		width = 120 // Cap max width for readability
	}
	ui.boxWidth = width
}

// Helper functions

func (ui *ScannerUI) drawBox(title string, lines []string) string {
	// Always use the fixed box width
	width := ui.boxWidth
	if width == 0 {
		// Fallback if not initialized
		width = 80
	}

	var result strings.Builder

	// Top border with title
	result.WriteString(ui.drawBoxTop(title, width))

	// Content lines
	for _, line := range lines {
		result.WriteString(ui.drawBoxLine(line, width))
	}

	// Bottom border
	result.WriteString(ui.drawBoxBottom(width))

	return result.String()
}

// drawBoxTop draws the top border with title.
func (ui *ScannerUI) drawBoxTop(title string, width int) string {
	// Format: ┌─ Title ─...─┐
	var result strings.Builder
	result.WriteString(colorCyan + "┌")

	if title != "" {
		// Add title with one dash on each side
		result.WriteString("─ " + colorBold + title + colorReset + colorCyan + " ─")
		titleLen := ui.visualLength(title) + 4 // "─ " + title + " ─"
		remaining := width - 2 - titleLen      // 2 for ┌┐
		if remaining > 0 {
			result.WriteString(strings.Repeat("─", remaining))
		}
	} else {
		// No title, just dashes
		result.WriteString(strings.Repeat("─", width-2))
	}

	result.WriteString("┐" + colorReset + "\n")
	return result.String()
}

// drawBoxLine draws a content line with proper padding.
func (ui *ScannerUI) drawBoxLine(content string, width int) string {
	// Format: │ content...padding │
	var result strings.Builder
	result.WriteString(colorCyan + "│ " + colorReset)

	// Check if this is a table separator line (contains ┼)
	isSeparator := strings.Contains(content, "┼")

	// Available space for content
	contentWidth := width - 4 // "│ " and " │"
	if isSeparator {
		contentWidth = width - 3 // "│ " and "│" (no trailing space for separator)
	}
	contentLen := ui.visualLength(content)

	if contentLen <= contentWidth {
		// Content fits, add padding
		result.WriteString(content)
		if !isSeparator {
			// Normal line - add padding to fill the box
			result.WriteString(strings.Repeat(" ", contentWidth-contentLen))
		}
	} else {
		// Content too long, truncate with ellipsis at the end
		// Only add ellipsis if there's room for it
		if contentWidth > 4 {
			truncated := ui.truncatePreservingANSI(content, contentWidth-4)
			result.WriteString(truncated + " ...")
		} else {
			// Very narrow, just truncate without ellipsis
			truncated := ui.truncatePreservingANSI(content, contentWidth)
			result.WriteString(truncated)
		}
	}

	if isSeparator {
		// For separator lines, no space before the closing border
		result.WriteString(colorCyan + "│" + colorReset + "\n")
	} else {
		// For normal lines, add space before the closing border
		result.WriteString(" " + colorCyan + "│" + colorReset + "\n")
	}
	return result.String()
}

// drawBoxBottom draws the bottom border.
func (ui *ScannerUI) drawBoxBottom(width int) string {
	return colorCyan + "└" + strings.Repeat("─", width-2) + "┘" + colorReset + "\n"
}

// smartTruncate truncates content intelligently, preserving ANSI codes.
func (ui *ScannerUI) smartTruncate(s string, maxWidth int) string {
	if maxWidth <= 0 {
		return ""
	}

	visualLen := ui.visualLength(s)
	if visualLen <= maxWidth {
		return s
	}

	// For very short widths, just truncate without ellipsis
	if maxWidth < 3 {
		return ui.truncatePreservingANSI(s, maxWidth)
	}

	// Otherwise, truncate and add ellipsis
	truncated := ui.truncatePreservingANSI(s, maxWidth-3)
	return truncated + "..."
}

// truncatePreservingANSI truncates while preserving ANSI color codes.
func (ui *ScannerUI) truncatePreservingANSI(s string, maxWidth int) string {
	var result strings.Builder
	visibleCount := 0
	inAnsi := false
	lastAnsiCode := ""

	for _, ch := range s {
		if ch == '\033' {
			inAnsi = true
			lastAnsiCode = string(ch)
			continue
		}

		if inAnsi {
			lastAnsiCode += string(ch)
			if ch == 'm' {
				result.WriteString(lastAnsiCode)
				inAnsi = false
				lastAnsiCode = ""
			}
		} else {
			if visibleCount >= maxWidth {
				break
			}
			result.WriteRune(ch)
			visibleCount++
		}
	}

	return result.String()
}

func (ui *ScannerUI) getRepoIcon(status string) string {
	switch status {
	case RepoStatusPending:
		return colorGray + "○" + colorReset
	case RepoStatusCloning:
		return colorYellow + "⟳" + colorReset
	case RepoStatusComplete:
		return colorGreen + "✓" + colorReset
	case RepoStatusFailed:
		return colorRed + "✗" + colorReset
	default:
		return "?"
	}
}

func (ui *ScannerUI) getScannerIcon(status string) string {
	switch status {
	case models.StatusPending:
		return colorGray + "○" + colorReset
	case models.StatusStarting:
		return colorBlue + "🚀" + colorReset
	case models.StatusRunning:
		return colorYellow + "⟳" + colorReset
	case models.StatusSuccess:
		return colorGreen + "✓" + colorReset
	case models.StatusFailed:
		return colorRed + "✗" + colorReset
	case models.StatusSkipped:
		return colorGray + "⏭" + colorReset
	default:
		return "?"
	}
}

func (ui *ScannerUI) getScannerStatusText(status string) string {
	switch status {
	case models.StatusPending:
		return "Pending"
	case models.StatusStarting:
		return "Starting"
	case models.StatusRunning:
		return "Running"
	case models.StatusSuccess:
		return "Complete"
	case models.StatusFailed:
		return "Failed"
	case models.StatusSkipped:
		return "Skipped"
	default:
		return "Unknown"
	}
}

func (ui *ScannerUI) getScannerProgress(status *models.ScannerStatus) string {
	if status.Status == models.StatusFailed && status.Message != "" {
		return status.Message
	}

	if status.Status == models.StatusSuccess {
		if status.TotalFindings == 0 {
			return "No findings"
		}
		// Build detailed severity summary
		parts := []string{}
		if c := status.FindingCounts["critical"]; c > 0 {
			parts = append(parts, fmt.Sprintf("%d crit", c))
		}
		if h := status.FindingCounts["high"]; h > 0 {
			parts = append(parts, fmt.Sprintf("%d high", h))
		}
		if m := status.FindingCounts["medium"]; m > 0 {
			parts = append(parts, fmt.Sprintf("%d med", m))
		}
		if l := status.FindingCounts["low"]; l > 0 {
			parts = append(parts, fmt.Sprintf("%d low", l))
		}
		return fmt.Sprintf("%d findings: %s", status.TotalFindings, strings.Join(parts, ", "))
	}

	if status.Total > 0 {
		if status.Message != "" {
			return fmt.Sprintf("[%d/%d] %s", status.Current, status.Total, status.Message)
		}
		return fmt.Sprintf("Progress: %d/%d", status.Current, status.Total)
	}

	if status.Message != "" {
		return status.Message
	}

	return "Initializing..."
}

func (ui *ScannerUI) getSortedRepoNames() []string {
	names := make([]string, 0, len(ui.repoStatuses))
	for name := range ui.repoStatuses {
		names = append(names, name)
	}
	// Simple sort
	for i := range names {
		for j := i + 1; j < len(names); j++ {
			if names[i] > names[j] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	return names
}

// Removed old padRight and truncate functions - use padOrTruncate and smartTruncate instead

func (ui *ScannerUI) visualLength(s string) int {
	// Remove ANSI escape sequences for length calculation
	clean := ui.stripANSI(s)
	// Count runes (visual characters) not bytes
	return len([]rune(clean))
}

func (ui *ScannerUI) stripANSI(s string) string {
	// Remove ANSI escape sequences
	clean := s
	for _, code := range []string{colorReset, colorRed, colorGreen, colorYellow, colorBlue, colorMagenta, colorCyan, colorGray, colorBold} {
		clean = strings.ReplaceAll(clean, code, "")
	}
	// Also remove other ANSI sequences
	for strings.Contains(clean, "\033[") {
		start := strings.Index(clean, "\033[")
		end := strings.Index(clean[start:], "m")
		if end == -1 {
			break
		}
		clean = clean[:start] + clean[start+end+1:]
	}
	return clean
}

func (ui *ScannerUI) getTermWidth() int {
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || width <= 0 {
		return 80 // Default width
	}
	return width
}

func (ui *ScannerUI) getTermHeight() int {
	_, height, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || height <= 0 {
		return 25 // Default height
	}
	return height
}
