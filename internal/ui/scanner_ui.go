// Package ui provides terminal user interface components for the scanner.
package ui

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

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

// NewScannerUI creates a new scanner UI instance.
func NewScannerUI(config Config) *ScannerUI {
	return &ScannerUI{
		config:          config,
		repoStatuses:    make(map[string]RepoStatus),
		scannerStatuses: make(map[string]*models.ScannerStatus),
		errorMessages:   []string{},
		stopChan:        make(chan bool),
	}
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

	_, _ = os.Stdout.WriteString(ui.drawBox(
		"─ Prismatic Security Scanner ─",
		[]string{
			fmt.Sprintf("Output: %s", ui.config.OutputDir),
			fmt.Sprintf("Client: %s | Environment: %s | Elapsed: %s",
				ui.config.ClientName, ui.config.Environment, elapsed),
		},
	))
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

		line := fmt.Sprintf("%s %-15s %s", icon, repo.Name, status)
		lines = append(lines, line)
	}

	_, _ = os.Stdout.WriteString(ui.drawBox("─ Repository Preparation ─", lines))
}

func (ui *ScannerUI) renderScanners() {
	// Create header
	lines := []string{
		"Scanner     │ Status      │ Time   │ Progress                        ",
		"────────────┼─────────────┼────────┼─────────────────────────────────",
	}

	// Add scanner rows
	for _, name := range ui.getSortedScannerNames() {
		status := ui.scannerStatuses[name]
		if status == nil {
			// Show pending scanners that haven't started yet
			line := fmt.Sprintf("%-11s │ ○ Pending   │ -      │ Waiting to start", name)
			lines = append(lines, line)
			continue
		}

		icon := ui.getScannerIcon(status.Status)
		statusText := ui.getScannerStatusText(status.Status)
		timeStr := "-"
		if status.ElapsedTime != "" {
			timeStr = status.ElapsedTime
		}

		progress := ui.getScannerProgress(status)

		line := fmt.Sprintf("%-11s │ %s %-9s │ %-6s │ %-31s",
			name, icon, statusText, timeStr, ui.truncate(progress, 31))
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

	summary := fmt.Sprintf("Total: %-4d  Critical: %-3d  High: %-3d  Medium: %-3d  Low: %-3d",
		total, bySeverity["critical"], bySeverity["high"],
		bySeverity["medium"], bySeverity["low"])

	_, _ = os.Stdout.WriteString(ui.drawBox("─ Finding Summary ─", []string{summary}))
}

func (ui *ScannerUI) renderErrors() {
	_, _ = os.Stdout.WriteString(ui.drawBox("─ Recent Errors ─", ui.errorMessages))
}

// Helper functions

func (ui *ScannerUI) drawBox(title string, lines []string) string {
	width := ui.getTermWidth()
	if width > 100 {
		width = 100 // Cap max width
	}

	var result strings.Builder

	// Top border
	result.WriteString("┌")
	result.WriteString(title)
	remaining := width - len(title) - 2
	result.WriteString(strings.Repeat("─", remaining))
	result.WriteString("┐\n")

	// Content lines
	for _, line := range lines {
		result.WriteString("│ ")
		result.WriteString(ui.padRight(line, width-4))
		result.WriteString(" │\n")
	}

	// Bottom border
	result.WriteString("└")
	result.WriteString(strings.Repeat("─", width-2))
	result.WriteString("┘\n")

	return result.String()
}

func (ui *ScannerUI) getRepoIcon(status string) string {
	switch status {
	case RepoStatusPending:
		return "○"
	case RepoStatusCloning:
		return "⟳"
	case RepoStatusComplete:
		return "✓"
	case RepoStatusFailed:
		return "✗"
	default:
		return "?"
	}
}

func (ui *ScannerUI) getScannerIcon(status string) string {
	switch status {
	case models.StatusPending:
		return "○"
	case models.StatusStarting:
		return "🚀"
	case models.StatusRunning:
		return "⟳"
	case models.StatusSuccess:
		return "✓"
	case models.StatusFailed:
		return "✗"
	case models.StatusSkipped:
		return "⏭"
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
		// Build compact severity summary
		parts := []string{}
		if c := status.FindingCounts["critical"]; c > 0 {
			parts = append(parts, fmt.Sprintf("%d critical", c))
		}
		if h := status.FindingCounts["high"]; h > 0 {
			parts = append(parts, fmt.Sprintf("%d high", h))
		}
		if status.TotalFindings > 0 {
			return fmt.Sprintf("%d findings (%s)", status.TotalFindings, strings.Join(parts, ", "))
		}
	}

	if status.Total > 0 {
		if status.Message != "" {
			return fmt.Sprintf("[%d/%d] %s", status.Current, status.Total, status.Message)
		}
		return fmt.Sprintf("[%d/%d]", status.Current, status.Total)
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

func (ui *ScannerUI) getSortedScannerNames() []string {
	// Define preferred order
	order := []string{"trivy", "kubescape", "nuclei", "gitleaks", "prowler", "checkov"}
	return order
}

func (ui *ScannerUI) padRight(s string, width int) string {
	if len(s) >= width {
		return s[:width]
	}
	return s + strings.Repeat(" ", width-len(s))
}

func (ui *ScannerUI) truncate(s string, width int) string {
	if len(s) <= width {
		return s
	}
	if width > 3 {
		return s[:width-3] + "..."
	}
	return s[:width]
}

func (ui *ScannerUI) getTermWidth() int {
	// Default width
	return 80
}

func (ui *ScannerUI) getTermHeight() int {
	// Default height
	return 25
}
