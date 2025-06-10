// Package ui provides terminal user interface components for the scanner.
package ui

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"

	"github.com/Veraticus/prismatic/internal/models"
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
	close(ui.stopChan)
	// Show cursor and move to bottom
	_, _ = os.Stdout.WriteString("\033[?25h")
	_, _ = fmt.Fprintf(os.Stdout, "\033[%d;1H\n", ui.getTermHeight())
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

func (ui *ScannerUI) renderHeader() {
	elapsed := time.Since(ui.config.StartTime).Round(time.Second)

	// Calculate available width
	availableWidth := ui.boxWidth - 4

	// Format header lines with proper padding
	lines := []string{
		fmt.Sprintf("%-*s", availableWidth, fmt.Sprintf("Output: %s", ui.config.OutputDir)),
		fmt.Sprintf("%-*s", availableWidth, fmt.Sprintf("Client: %s | Environment: %s | Elapsed: %s",
			ui.config.ClientName, ui.config.Environment, elapsed)),
	}

	_, _ = os.Stdout.WriteString(ui.drawBox(
		"─ Prismatic Security Scanner ─",
		lines,
	))
}

func (ui *ScannerUI) renderRepositories() {
	if len(ui.repoStatuses) == 0 {
		return
	}

	// Calculate available width for repository display
	availableWidth := ui.boxWidth - 4 // Account for box borders
	repoNameWidth := 20
	statusWidth := availableWidth - repoNameWidth - 2 // 2 for icon and space

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

		// Format with proper padding
		line := fmt.Sprintf("%s %-*s %-*s",
			icon,
			repoNameWidth, ui.truncate(repo.Name, repoNameWidth),
			statusWidth, ui.truncate(status, statusWidth))
		lines = append(lines, line)
	}

	_, _ = os.Stdout.WriteString(ui.drawBox("─ Repository Preparation ─", lines))
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

	// Calculate column widths based on available space
	// We need 4 columns with separators: Scanner | Status | Time | Progress
	// Account for: "│ " (2) at start, " │" (2) at end, and 3x " │ " (9) between columns
	availableWidth := ui.boxWidth - 4 - 9
	if availableWidth < 60 {
		availableWidth = 60 // Minimum for readability
	}

	// Allocate column widths proportionally
	// Give more space to progress column for better readability
	scannerWidth := 11
	statusWidth := 10
	timeWidth := 8
	progressWidth := availableWidth - scannerWidth - statusWidth - timeWidth
	if progressWidth < 30 {
		progressWidth = 30 // Minimum for progress column
	}

	// Create header
	header := fmt.Sprintf("%s%-*s │ %-*s │ %-*s │ %-*s%s",
		colorBold,
		scannerWidth, "Scanner",
		statusWidth, "Status",
		timeWidth, "Time",
		progressWidth, "Progress",
		colorReset)

	// Create separator with proper width
	separator := colorGray +
		strings.Repeat("─", scannerWidth) + "┼" +
		strings.Repeat("─", statusWidth+2) + "┼" +
		strings.Repeat("─", timeWidth+2) + "┼" +
		strings.Repeat("─", progressWidth+2) +
		colorReset

	lines := []string{header, separator}

	// Add scanner rows
	for _, name := range activeScanners {
		status := ui.scannerStatuses[name]
		if status == nil {
			continue
		}

		icon := ui.getScannerIcon(status.Status)
		statusText := ui.getScannerStatusText(status.Status)
		timeStr := "-"
		if status.ElapsedTime != "" {
			timeStr = status.ElapsedTime
		}

		progress := ui.getScannerProgress(status)

		// Color the row based on status
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

		// Format row with proper column widths
		// Account for icon taking 2 visual spaces (icon + space)
		line := fmt.Sprintf("%s%-*s%s │ %s %-*s │ %-*s │ %-*s",
			rowColor, scannerWidth, ui.truncate(name, scannerWidth), colorReset,
			icon, statusWidth-2, ui.truncate(statusText, statusWidth-2),
			timeWidth, ui.truncate(timeStr, timeWidth),
			progressWidth, ui.truncate(progress, progressWidth))
		lines = append(lines, line)
	}

	_, _ = os.Stdout.WriteString(ui.drawBox("─ Scanner Status ─", lines))
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

	// Calculate space for summary display
	availableWidth := ui.boxWidth - 4

	// Build colored summary with proper spacing
	summaryItems := []struct {
		label string
		color string
		value int
	}{
		{"Total", total, colorBold},
		{"Critical", bySeverity["critical"], colorRed},
		{"High", bySeverity["high"], colorYellow},
		{"Medium", bySeverity["medium"], colorBlue},
		{"Low", bySeverity["low"], colorGreen},
		{"Info", bySeverity["info"], colorCyan},
	}

	parts := []string{}
	for _, item := range summaryItems {
		if item.label == "Total" || item.value > 0 {
			color := item.color
			if item.label != "Total" && item.value == 0 {
				color = colorGray
			}
			parts = append(parts, fmt.Sprintf("%s%s: %d%s", color, item.label, item.value, colorReset))
		}
	}

	// Calculate spacing between items
	itemsText := strings.Join(parts, "  ")
	if ui.visualLength(itemsText) < availableWidth {
		// We have space, use it
		summary := itemsText
		_, _ = os.Stdout.WriteString(ui.drawBox("─ Finding Summary ─", []string{summary}))
	} else {
		// Split into multiple lines if needed
		lines := []string{}
		currentLine := []string{}
		currentLength := 0

		for _, part := range parts {
			partLength := ui.visualLength(part) + 2 // +2 for spacing
			if currentLength > 0 && currentLength+partLength > availableWidth {
				lines = append(lines, strings.Join(currentLine, "  "))
				currentLine = []string{part}
				currentLength = ui.visualLength(part)
			} else {
				currentLine = append(currentLine, part)
				currentLength += partLength
			}
		}
		if len(currentLine) > 0 {
			lines = append(lines, strings.Join(currentLine, "  "))
		}

		_, _ = os.Stdout.WriteString(ui.drawBox("─ Finding Summary ─", lines))
	}
}

func (ui *ScannerUI) renderErrors() {
	// Color errors in red
	coloredErrors := make([]string, len(ui.errorMessages))
	for i, err := range ui.errorMessages {
		coloredErrors[i] = colorRed + err + colorReset
	}
	_, _ = os.Stdout.WriteString(ui.drawBox("─ Recent Errors ─", coloredErrors))
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

	// Top border with colored title
	result.WriteString(colorCyan + "┌")
	result.WriteString(colorBold + title + colorReset + colorCyan)
	titleLen := ui.visualLength(title)
	remaining := width - titleLen - 2
	if remaining > 0 {
		result.WriteString(strings.Repeat("─", remaining))
	}
	result.WriteString("┐" + colorReset + "\n")

	// Content lines
	for _, line := range lines {
		result.WriteString(colorCyan + "│ " + colorReset)

		// Pad line to proper width considering ANSI codes
		lineLen := ui.visualLength(line)
		if lineLen < width-4 {
			result.WriteString(line)
			result.WriteString(strings.Repeat(" ", width-4-lineLen))
		} else {
			// Truncate if too long
			result.WriteString(ui.truncate(line, width-4))
		}

		result.WriteString(" " + colorCyan + "│" + colorReset + "\n")
	}

	// Bottom border
	result.WriteString(colorCyan + "└")
	result.WriteString(strings.Repeat("─", width-2))
	result.WriteString("┘" + colorReset + "\n")

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

func (ui *ScannerUI) padRight(s string, width int) string {
	if len(s) >= width {
		return s[:width]
	}
	return s + strings.Repeat(" ", width-len(s))
}

func (ui *ScannerUI) truncate(s string, width int) string {
	// Calculate visual length without ANSI codes
	visualLen := ui.visualLength(s)
	if visualLen <= width {
		return s
	}

	// Need to truncate - handle ANSI codes properly
	// This is a simple implementation that strips ANSI codes
	clean := ui.stripANSI(s)
	if len(clean) <= width {
		return s
	}

	if width > 3 {
		return clean[:width-3] + "..."
	}
	return clean[:width]
}

func (ui *ScannerUI) visualLength(s string) int {
	// Remove ANSI escape sequences for length calculation
	clean := ui.stripANSI(s)
	return len(clean)
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
