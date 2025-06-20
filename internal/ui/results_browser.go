package ui

import (
	"context"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/joshsymonds/prismatic/internal/database"
)

// ResultsBrowser represents the results browser page.
type ResultsBrowser struct {
	db          *database.DB
	currentScan *database.Scan
	errorMsg    string
	filter      database.FindingFilter
	findings    []*database.Finding
	cursor      int
	width       int
	height      int
	loading     bool
}

// NewResultsBrowser creates a new results browser.
func NewResultsBrowser() *ResultsBrowser {
	return &ResultsBrowser{
		findings: []*database.Finding{},
		cursor:   0,
		loading:  false,
		filter: database.FindingFilter{
			Limit:  1000, // Reasonable limit for UI
			Offset: 0,
		},
	}
}

// LoadFindingsMsg is sent when findings are loaded from the database.
type LoadFindingsMsg struct {
	Err      error
	Findings []*database.Finding
}

// SetScanMsg is sent to set the current scan to browse.
type SetScanMsg struct {
	Scan *database.Scan
}

// Init initializes the results browser.
func (r *ResultsBrowser) Init() tea.Cmd {
	if r.db != nil && r.currentScan != nil {
		r.loading = true
		return r.loadFindings
	}
	return nil
}

// loadFindings loads findings from the database.
func (r *ResultsBrowser) loadFindings() tea.Msg {
	if r.db == nil {
		return LoadFindingsMsg{Err: fmt.Errorf("database not initialized")}
	}

	if r.currentScan == nil {
		return LoadFindingsMsg{Err: fmt.Errorf("no scan selected")}
	}

	ctx := context.Background()

	findings, err := r.db.GetFindings(ctx, r.currentScan.ID, r.filter)
	if err != nil {
		return LoadFindingsMsg{Err: fmt.Errorf("loading findings: %w", err)}
	}

	return LoadFindingsMsg{Findings: findings}
}

// Update handles results browser updates.
func (r *ResultsBrowser) Update(msg tea.Msg) (*ResultsBrowser, tea.Cmd) {
	switch msg := msg.(type) {
	case SetScanMsg:
		r.currentScan = msg.Scan
		if r.db != nil {
			r.loading = true
			return r, r.loadFindings
		}
		return r, nil

	case LoadFindingsMsg:
		r.loading = false
		if msg.Err != nil {
			r.errorMsg = msg.Err.Error()
		} else {
			r.findings = msg.Findings
			if len(r.findings) > 0 && r.cursor >= len(r.findings) {
				r.cursor = len(r.findings) - 1
			}
		}
		return r, nil

	case tea.KeyMsg:
		if r.loading {
			return r, nil // Ignore keys while loading
		}

		switch msg.String() {
		case "j", "down":
			if r.cursor < len(r.findings)-1 {
				r.cursor++
			}
		case "k", "up":
			if r.cursor > 0 {
				r.cursor--
			}
		case "g":
			r.cursor = 0
		case "G":
			if len(r.findings) > 0 {
				r.cursor = len(r.findings) - 1
			}
		case "enter":
			if r.cursor < len(r.findings) {
				// Navigate to finding details
				return r, func() tea.Msg {
					return FindingDetailsMsg{Finding: r.findings[r.cursor]}
				}
			}
		// Filtering
		case "f":
			// TODO: Show filter menu
		case "s":
			// TODO: Show suppression menu for current finding
		case "R":
			// Refresh findings
			r.loading = true
			return r, r.loadFindings
		}
	}
	return r, nil
}

// View renders the results browser.
func (r *ResultsBrowser) View() string {
	var b strings.Builder

	// Title
	title := TitleStyle.Render("Results Browser")
	b.WriteString(lipgloss.PlaceHorizontal(r.width, lipgloss.Center, title))
	b.WriteString("\n\n")

	// Summary stats
	stats := r.getStats()
	summaryStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#333333")).
		Padding(1, 2).
		Width(r.width - 4)

	summary := fmt.Sprintf(
		"Total: %d | Critical: %s | High: %s | Medium: %s | Low: %s",
		stats["total"],
		r.colorBySeverity("critical", stats["critical"]),
		r.colorBySeverity("high", stats["high"]),
		r.colorBySeverity("medium", stats["medium"]),
		r.colorBySeverity("low", stats["low"]),
	)
	b.WriteString(summaryStyle.Render(summary))
	b.WriteString("\n\n")

	// Findings list
	switch {
	case r.loading:
		b.WriteString(lipgloss.PlaceHorizontal(r.width, lipgloss.Center, "Loading findings..."))
	case r.errorMsg != "":
		errorStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000"))
		b.WriteString(lipgloss.PlaceHorizontal(r.width, lipgloss.Center, errorStyle.Render("Error: "+r.errorMsg)))
	case len(r.findings) == 0:
		b.WriteString(lipgloss.PlaceHorizontal(r.width, lipgloss.Center, "No findings to display"))
	default:
		// Table header
		headerStyle := lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00FFFF")).
			BorderBottom(true).
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("#333333"))

		headers := []string{
			r.padRight("Severity", 10),
			r.padRight("Scanner", 12),
			r.padRight("Resource", 30),
			r.padRight("Title", 60),
		}

		b.WriteString("  ")
		b.WriteString(headerStyle.Render(strings.Join(headers, " ")))
		b.WriteString("\n\n")

		// Finding rows
		for i, finding := range r.findings {
			cursor := "  "
			style := NormalItemStyle

			if r.cursor == i {
				cursor = "▸ "
				style = SelectedItemStyle
			}

			// Color severity
			severityStyle := r.getSeverityStyle(string(finding.Severity))
			severity := severityStyle.Render(r.padRight(string(finding.Severity), 10))

			row := fmt.Sprintf("%s%s %s %s %s",
				cursor,
				severity,
				r.padRight(finding.Scanner, 12),
				r.padRight(finding.Resource, 30),
				r.padRight(finding.Title, 60),
			)

			b.WriteString(style.Render(row))
			b.WriteString("\n")

			// Show only visible items based on terminal height
			if i > r.height-15 {
				b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#666666")).Render(fmt.Sprintf("  ... and %d more findings", len(r.findings)-i-1)))
				break
			}
		}
	}

	// Help
	b.WriteString("\n\n")
	help := HelpStyle.Render("Navigate: j/k • View: Enter • Filter: f • Suppress: s • Refresh: R • Back: Esc")
	b.WriteString(lipgloss.PlaceHorizontal(r.width, lipgloss.Center, help))

	return b.String()
}

// SetSize updates the page dimensions.
func (r *ResultsBrowser) SetSize(width, height int) {
	r.width = width
	r.height = height
}

// getStats calculates finding statistics.
func (r *ResultsBrowser) getStats() map[string]int {
	stats := map[string]int{
		"total":    len(r.findings),
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}

	for _, f := range r.findings {
		switch f.Severity {
		case database.SeverityCritical:
			stats["critical"]++
		case database.SeverityHigh:
			stats["high"]++
		case database.SeverityMedium:
			stats["medium"]++
		case database.SeverityLow:
			stats["low"]++
		case database.SeverityInfo:
			stats["info"]++
		}
	}

	return stats
}

// colorBySeverity returns colored text based on severity.
func (r *ResultsBrowser) colorBySeverity(severity string, count int) string {
	var color lipgloss.Color
	switch severity {
	case "critical":
		color = CriticalColor
	case "high":
		color = HighColor
	case "medium":
		color = MediumColor
	case "low":
		color = LowColor
	default:
		color = InfoColor
	}

	return lipgloss.NewStyle().Foreground(color).Render(fmt.Sprintf("%d", count))
}

// padRight pads a string to the right with spaces.
func (r *ResultsBrowser) padRight(str string, length int) string {
	if len(str) >= length {
		return str[:length-1] + "…"
	}
	return str + strings.Repeat(" ", length-len(str))
}

// getSeverityStyle returns the style for a severity level.
func (r *ResultsBrowser) getSeverityStyle(severity string) lipgloss.Style {
	var color lipgloss.Color
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		color = CriticalColor
	case "HIGH":
		color = HighColor
	case "MEDIUM":
		color = MediumColor
	case "LOW":
		color = LowColor
	default:
		color = InfoColor
	}
	return lipgloss.NewStyle().Foreground(color).Bold(true)
}

// SetDatabase sets the database connection.
func (r *ResultsBrowser) SetDatabase(db *database.DB) {
	r.db = db
}

// SetScan sets the current scan to browse.
func (r *ResultsBrowser) SetScan(scan *database.Scan) {
	r.currentScan = scan
}
