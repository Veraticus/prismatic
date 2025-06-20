// Package ui provides terminal user interface components for the scanner.
package ui

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/joshsymonds/prismatic/internal/database"
)

// FindingDetailsMsg is sent when viewing finding details.
type FindingDetailsMsg struct {
	Finding *database.Finding
}

// FindingDetails represents the finding details view.
type FindingDetails struct {
	finding  *database.Finding
	viewport viewport.Model
	width    int
	height   int
	ready    bool
}

// NewFindingDetails creates a new finding details view.
func NewFindingDetails() *FindingDetails {
	return &FindingDetails{
		viewport: viewport.New(0, 0),
	}
}

// Init initializes the finding details view.
func (f *FindingDetails) Init() tea.Cmd {
	return nil
}

// Update handles messages for the finding details view.
func (f *FindingDetails) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var (
		cmd  tea.Cmd
		cmds []tea.Cmd
	)

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		f.width = msg.Width
		f.height = msg.Height
		if !f.ready {
			// Initialize viewport with window size
			f.viewport = viewport.New(msg.Width-4, msg.Height-6)
			f.viewport.YPosition = 0
			f.viewport.KeyMap = viewport.DefaultKeyMap()
			f.ready = true
		} else {
			f.viewport.Width = msg.Width - 4
			f.viewport.Height = msg.Height - 6
		}
		if f.finding != nil {
			f.updateContent()
		}

	case FindingDetailsMsg:
		f.finding = msg.Finding
		f.updateContent()
		f.viewport.GotoTop()

	case tea.KeyMsg:
		switch msg.String() {
		case "esc", "q":
			// Go back to results browser
			return f, func() tea.Msg { return NavigateToPageMsg{Page: ResultsBrowserPage} }
		case "s":
			// Suppress finding
			if f.finding != nil {
				// TODO: Show suppression modal
				return f, nil
			}
		case "c":
			// Copy finding ID
			// TODO: Implement clipboard copy
			return f, nil
		case "e":
			// Export finding
			// TODO: Implement export functionality
			return f, nil
		}
	}

	// Handle viewport updates
	f.viewport, cmd = f.viewport.Update(msg)
	cmds = append(cmds, cmd)

	return f, tea.Batch(cmds...)
}

// View renders the finding details view.
func (f *FindingDetails) View() string {
	if !f.ready {
		return "\n  Initializing..."
	}

	if f.finding == nil {
		return lipgloss.NewStyle().
			Width(f.width).
			Height(f.height).
			Align(lipgloss.Center, lipgloss.Center).
			Render("No finding selected")
	}

	// Header
	header := f.renderHeader()

	// Footer with shortcuts
	footer := f.renderFooter()

	// Content in viewport
	return lipgloss.JoinVertical(
		lipgloss.Left,
		header,
		f.viewport.View(),
		footer,
	)
}

// updateContent updates the viewport content with formatted finding details.
func (f *FindingDetails) updateContent() {
	if f.finding == nil {
		return
	}

	content := f.renderFindingContent()
	f.viewport.SetContent(content)
}

// renderHeader renders the header with finding title and severity.
func (f *FindingDetails) renderHeader() string {
	if f.finding == nil {
		return ""
	}

	severityStyle := getSeverityStyle(string(f.finding.Severity))
	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("86")).
		Width(f.width - 20)

	title := titleStyle.Render(truncateString(f.finding.Title, f.width-20))
	severity := severityStyle.Render(strings.ToUpper(string(f.finding.Severity)))

	header := lipgloss.JoinHorizontal(
		lipgloss.Left,
		title,
		lipgloss.NewStyle().Width(2).Render(" "),
		severity,
	)

	return lipgloss.NewStyle().
		BorderStyle(lipgloss.NormalBorder()).
		BorderBottom(true).
		BorderForeground(lipgloss.Color("240")).
		Width(f.width).
		Padding(0, 2).
		Render(header)
}

// renderFooter renders the footer with keyboard shortcuts.
func (f *FindingDetails) renderFooter() string {
	shortcuts := []string{
		"[ESC/q] Back",
		"[↑↓/j/k] Scroll",
		"[s] Suppress",
		"[c] Copy ID",
		"[e] Export",
	}

	footerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240")).
		Width(f.width).
		Align(lipgloss.Center).
		BorderStyle(lipgloss.NormalBorder()).
		BorderTop(true).
		BorderForeground(lipgloss.Color("240"))

	return footerStyle.Render(strings.Join(shortcuts, "  "))
}

// renderFindingContent renders the complete finding details.
func (f *FindingDetails) renderFindingContent() string {
	var sections []string

	// Basic Information
	sections = append(sections, f.renderBasicInfo())

	// Description
	if f.finding.Description != "" {
		sections = append(sections, f.renderSection("Description", f.finding.Description))
	}

	// For database.Finding, we only have limited fields available
	// Additional information would need to come from TechnicalDetails JSON

	// Technical Details
	if f.finding.TechnicalDetails != nil {
		sections = append(sections, f.renderTechnicalDetails())
	}

	return strings.Join(sections, "\n\n")
}

// renderBasicInfo renders basic finding information.
func (f *FindingDetails) renderBasicInfo() string {
	infoStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("246"))
	labelStyle := lipgloss.NewStyle().Bold(true).Width(15)

	var lines []string

	lines = append(lines,
		lipgloss.JoinHorizontal(lipgloss.Left,
			labelStyle.Render("ID:"),
			infoStyle.Render(fmt.Sprintf("%d", f.finding.ID)),
		),
		lipgloss.JoinHorizontal(lipgloss.Left,
			labelStyle.Render("Scanner:"),
			infoStyle.Render(f.finding.Scanner),
		),
		lipgloss.JoinHorizontal(lipgloss.Left,
			labelStyle.Render("Resource:"),
			infoStyle.Render(f.finding.Resource),
		),
		lipgloss.JoinHorizontal(lipgloss.Left,
			labelStyle.Render("Severity:"),
			infoStyle.Render(string(f.finding.Severity)),
		),
		lipgloss.JoinHorizontal(lipgloss.Left,
			labelStyle.Render("Created:"),
			infoStyle.Render(f.finding.CreatedAt.Format("2006-01-02 15:04:05")),
		))

	return strings.Join(lines, "\n")
}

// renderSection renders a section with title and content.
func (f *FindingDetails) renderSection(title, content string) string {
	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("86")).
		MarginBottom(1)

	contentStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("252")).
		Width(f.width - 6).
		PaddingLeft(2)

	return titleStyle.Render(title) + "\n" + contentStyle.Render(content)
}

// renderCodeBlock renders a code block with syntax highlighting.
// Currently unused but available for future enhancement.
/*
func (f *FindingDetails) renderCodeBlock(title, code, filename string) string {
	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("86")).
		MarginBottom(1)

	codeStyle := lipgloss.NewStyle().
		Background(lipgloss.Color("235")).
		Foreground(lipgloss.Color("252")).
		Padding(1, 2).
		Width(f.width - 6)

	header := titleStyle.Render(title)
	if filename != "" {
		header += " " + lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("("+filename+")")
	}

	return header + "\n" + codeStyle.Render(code)
}
*/

// renderTechnicalDetails renders technical details as formatted JSON.
func (f *FindingDetails) renderTechnicalDetails() string {
	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("86")).
		MarginBottom(1)

	var formatted string
	if f.finding.TechnicalDetails != nil {
		// Try to format as indented JSON
		if indented, err := json.MarshalIndent(f.finding.TechnicalDetails, "", "  "); err == nil {
			formatted = string(indented)
		} else {
			formatted = string(f.finding.TechnicalDetails)
		}
	}

	codeStyle := lipgloss.NewStyle().
		Background(lipgloss.Color("235")).
		Foreground(lipgloss.Color("252")).
		Padding(1, 2).
		Width(f.width - 6)

	return titleStyle.Render("Technical Details") + "\n" + codeStyle.Render(formatted)
}

// getSeverityStyle returns the style for a severity level.
func getSeverityStyle(severity string) lipgloss.Style {
	base := lipgloss.NewStyle().
		Bold(true).
		Padding(0, 2)

	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return base.Background(lipgloss.Color("197")).Foreground(lipgloss.Color("15"))
	case "HIGH":
		return base.Background(lipgloss.Color("208")).Foreground(lipgloss.Color("15"))
	case "MEDIUM":
		return base.Background(lipgloss.Color("214")).Foreground(lipgloss.Color("15"))
	case "LOW":
		return base.Background(lipgloss.Color("148")).Foreground(lipgloss.Color("15"))
	case "INFO":
		return base.Background(lipgloss.Color("86")).Foreground(lipgloss.Color("15"))
	default:
		return base.Background(lipgloss.Color("240")).Foreground(lipgloss.Color("15"))
	}
}

// maskSecret partially masks a secret for display.
func maskSecret(secret string) string {
	if len(secret) <= 8 {
		return strings.Repeat("*", len(secret))
	}

	// Show first 4 and last 4 characters
	return secret[:4] + strings.Repeat("*", len(secret)-8) + secret[len(secret)-4:]
}

// SetSize updates the dimensions of the finding details view.
func (f *FindingDetails) SetSize(width, height int) {
	f.width = width
	f.height = height
	if f.ready {
		f.viewport.Width = width - 4
		f.viewport.Height = height - 6
		f.updateContent()
	}
}

// truncateString truncates a string to fit within maxWidth.
func truncateString(s string, maxWidth int) string {
	if len(s) <= maxWidth {
		return s
	}
	if maxWidth < 3 {
		return s[:maxWidth]
	}
	return s[:maxWidth-3] + "..."
}
