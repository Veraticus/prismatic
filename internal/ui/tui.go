// Package ui provides terminal user interface components for the scanner.
package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/joshsymonds/prismatic/internal/database"
	"github.com/joshsymonds/prismatic/internal/enrichment"
	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/joshsymonds/prismatic/internal/report"
	"github.com/joshsymonds/prismatic/internal/storage"
	"github.com/joshsymonds/prismatic/pkg/logger"
)

// Page represents different pages in the TUI.
type Page int

const (
	// MainMenuPage is the main menu page.
	MainMenuPage Page = iota
	// ScannerConfigPage is the scanner configuration page.
	ScannerConfigPage
	// ScanProgressPage is the scan progress page.
	ScanProgressPage
	// ResultsBrowserPage is the results browser page.
	ResultsBrowserPage
	// FindingDetailsPage is the finding details page.
	FindingDetailsPage
	// ScanHistoryPage is the scan history page.
	ScanHistoryPage
)

// TUI represents the main TUI application.
type TUI struct {
	db *database.DB
}

// NewTUI creates a new TUI with database connection.
func NewTUI(db *database.DB) *TUI {
	return &TUI{db: db}
}

// Run starts the TUI application.
func (t *TUI) Run() error {
	model := NewTUIModel(t.db)
	p := tea.NewProgram(model, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// TUIModel represents the main TUI application state.
type TUIModel struct {
	db             *database.DB
	mainMenu       *MainMenu
	scanConfig     *ScanConfig
	scanProgress   *ScanProgress
	resultsBrowser *ResultsBrowser
	scanHistory    *ScanHistory
	findingDetails *FindingDetails
	pageHistory    []Page
	currentPage    Page
	width          int
	height         int
	quitting       bool
}

// NewTUIModel creates a new TUI application model.
func NewTUIModel(db *database.DB) *TUIModel {
	return &TUIModel{
		db:          db,
		currentPage: MainMenuPage,
		pageHistory: []Page{},
		mainMenu:    NewMainMenu(),
	}
}

// Init initializes the TUI.
func (m *TUIModel) Init() tea.Cmd {
	return tea.Batch(
		tea.EnterAltScreen,
		m.mainMenu.Init(),
	)
}

// Update handles all TUI updates.
func (m *TUIModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		// Update all pages with new size
		if m.mainMenu != nil {
			m.mainMenu.SetSize(msg.Width, msg.Height)
		}
		if m.scanProgress != nil {
			m.scanProgress.SetSize(msg.Width, msg.Height)
		}

	case tea.KeyMsg:
		// Global key bindings
		switch msg.String() {
		case "ctrl+c", "ctrl+q":
			m.quitting = true
			return m, tea.Quit
		case "esc":
			// Go back to previous page
			if len(m.pageHistory) > 0 {
				m.currentPage = m.pageHistory[len(m.pageHistory)-1]
				m.pageHistory = m.pageHistory[:len(m.pageHistory)-1]
			}
		}

	case NavigateToPageMsg:
		// Save current page to history
		m.pageHistory = append(m.pageHistory, m.currentPage)
		m.currentPage = msg.Page

		// Initialize the new page if needed
		switch m.currentPage {
		case ScannerConfigPage:
			if m.scanConfig == nil {
				m.scanConfig = NewScanConfig()
			}
			return m, m.scanConfig.Init()
		case ScanProgressPage:
			if m.scanProgress == nil {
				// TODO: Get config from scan config page
				m.scanProgress = NewScanProgress("test-client", "production", "./data/scans")
			}
			return m, m.scanProgress.Init()
		case ResultsBrowserPage:
			if m.resultsBrowser == nil {
				m.resultsBrowser = NewResultsBrowser()
				m.resultsBrowser.SetDatabase(m.db)
			}
			return m, m.resultsBrowser.Init()
		case ScanHistoryPage:
			if m.scanHistory == nil {
				m.scanHistory = NewScanHistory()
				m.scanHistory.SetDatabase(m.db)
			}
			return m, m.scanHistory.Init()
		case FindingDetailsPage:
			if m.findingDetails == nil {
				m.findingDetails = NewFindingDetails()
			}
			return m, m.findingDetails.Init()
		}

	case StartScanMsg:
		// Initialize scan progress with actual configuration
		m.scanProgress = NewScanProgress(msg.ClientName, msg.Environment, msg.OutputDir)
		// Save current page to history
		m.pageHistory = append(m.pageHistory, m.currentPage)
		m.currentPage = ScanProgressPage
		return m, m.scanProgress.Init()

	case FindingDetailsMsg:
		// Initialize finding details if needed
		if m.findingDetails == nil {
			m.findingDetails = NewFindingDetails()
		}
		// Pass the finding to the details page
		_, _ = m.findingDetails.Update(msg)
		// Navigate to the finding details page

	case GenerateReportMsg:
		// Generate report for the scan
		cmd := m.generateReport(msg.ScanID)
		return m, cmd

	case EnrichScanMsg:
		// Enrich findings for the scan
		cmd := m.enrichScan(msg.ScanID)
		return m, cmd

	case ShowMessageMsg:
		// TODO: Show modal with message
		_ = msg
		return m, nil

	}

	// Route updates to current page
	switch m.currentPage {
	case MainMenuPage:
		if m.mainMenu != nil {
			var cmd tea.Cmd
			m.mainMenu, cmd = m.mainMenu.Update(msg)
			cmds = append(cmds, cmd)
		}
	case ScannerConfigPage:
		if m.scanConfig != nil {
			var cmd tea.Cmd
			m.scanConfig, cmd = m.scanConfig.Update(msg)
			cmds = append(cmds, cmd)
		}
	case ScanProgressPage:
		if m.scanProgress != nil {
			var cmd tea.Cmd
			m.scanProgress, cmd = m.scanProgress.Update(msg)
			cmds = append(cmds, cmd)
		}
	case ResultsBrowserPage:
		if m.resultsBrowser != nil {
			var cmd tea.Cmd
			m.resultsBrowser, cmd = m.resultsBrowser.Update(msg)
			cmds = append(cmds, cmd)
		}
	case ScanHistoryPage:
		if m.scanHistory != nil {
			var cmd tea.Cmd
			m.scanHistory, cmd = m.scanHistory.Update(msg)
			cmds = append(cmds, cmd)
		}
	case FindingDetailsPage:
		if m.findingDetails != nil {
			var cmd tea.Cmd
			var model tea.Model
			model, cmd = m.findingDetails.Update(msg)
			if fd, ok := model.(*FindingDetails); ok {
				m.findingDetails = fd
			}
			cmds = append(cmds, cmd)
		}
	}

	return m, tea.Batch(cmds...)
}

// View renders the current page.
func (m *TUIModel) View() string {
	if m.quitting {
		return ""
	}

	switch m.currentPage {
	case MainMenuPage:
		if m.mainMenu != nil {
			return m.mainMenu.View()
		}
	case ScannerConfigPage:
		if m.scanConfig != nil {
			return m.scanConfig.View()
		}
	case ScanProgressPage:
		if m.scanProgress != nil {
			return m.scanProgress.View()
		}
	case ResultsBrowserPage:
		if m.resultsBrowser != nil {
			return m.resultsBrowser.View()
		}
	case ScanHistoryPage:
		if m.scanHistory != nil {
			return m.scanHistory.View()
		}
	case FindingDetailsPage:
		if m.findingDetails != nil {
			return m.findingDetails.View()
		}
	}

	return "Loading..."
}

// NavigateToPageMsg is sent to navigate to a different page.
type NavigateToPageMsg struct {
	Page Page
}

// GenerateReportMsg is sent to generate a report for a scan.
type GenerateReportMsg struct {
	ScanID int64
}

// EnrichScanMsg is sent to enrich findings for a scan.
type EnrichScanMsg struct {
	ScanID int64
}

// ShowMessageMsg displays a message to the user.
type ShowMessageMsg struct {
	Title   string
	Message string
	Type    string // "success", "error", "info"
}

// Style definitions.
var (
	// Colors matching the prismatic theme.
	CriticalColor = lipgloss.Color("#FF0000")
	HighColor     = lipgloss.Color("#FFA500")
	MediumColor   = lipgloss.Color("#FFFF00")
	LowColor      = lipgloss.Color("#0000FF")
	InfoColor     = lipgloss.Color("#808080")

	// Base styles.
	BaseStyle = lipgloss.NewStyle().
			Padding(1, 2)

	TitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00FFFF")).
			MarginBottom(1)

	SelectedItemStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#00FFFF")).
				Bold(true)

	NormalItemStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF"))

	HelpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#808080")).
			MarginTop(1)
)

// FormatShortcuts formats keyboard shortcuts with consistent styling.
func FormatShortcuts(shortcuts ...string) string {
	style := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#00FFFF")).
		Background(lipgloss.Color("#333333")).
		Padding(0, 1)

	formatted := make([]string, len(shortcuts))
	for i, s := range shortcuts {
		formatted[i] = style.Render(s)
	}

	return lipgloss.JoinHorizontal(lipgloss.Left, formatted...)
}

// generateReport generates a report for the given scan ID.
func (m *TUIModel) generateReport(scanID int64) tea.Cmd {
	return func() tea.Msg {
		// Get database from the model
		db := m.db
		if db == nil {
			return ShowMessageMsg{
				Title:   "Error",
				Message: "Database connection not available",
				Type:    "error",
			}
		}

		// Create storage
		store := storage.NewStorageWithLogger(db, logger.GetGlobalLogger())

		// Load scan metadata
		metadata, err := store.LoadScanResults(scanID)
		if err != nil {
			return ShowMessageMsg{
				Title:   "Error",
				Message: fmt.Sprintf("Failed to load scan results: %v", err),
				Type:    "error",
			}
		}

		// Get all findings from the scan
		ctx := context.Background()
		dbFindings, err := db.GetFindings(ctx, scanID, database.FindingFilter{})
		if err != nil {
			return ShowMessageMsg{
				Title:   "Error",
				Message: fmt.Sprintf("Failed to load findings: %v", err),
				Type:    "error",
			}
		}

		// Convert database findings to model findings
		findings := make([]models.Finding, 0, len(dbFindings))
		for _, dbFinding := range dbFindings {
			finding := convertDBFindingToModel(dbFinding)
			findings = append(findings, finding)
		}

		// Load enrichments if available
		enrichments, _, _ := store.LoadEnrichments(scanID)
		enrichmentMap := make(map[string]*enrichment.FindingEnrichment)
		for i := range enrichments {
			enrichmentMap[enrichments[i].FindingID] = &enrichments[i]
		}

		// Generate output path
		outputDir := "reports"
		if mkdirErr := os.MkdirAll(outputDir, 0750); mkdirErr != nil {
			return ShowMessageMsg{
				Title:   "Error",
				Message: fmt.Sprintf("Failed to create reports directory: %v", mkdirErr),
			}
		}
		outputFile := filepath.Join(outputDir, fmt.Sprintf("report-scan-%d.html", scanID))

		// Get HTML formatter
		htmlFormatter, err := report.GetFormat("html", logger.GetGlobalLogger())
		if err != nil {
			return ShowMessageMsg{
				Title:   "Error",
				Message: fmt.Sprintf("Failed to get HTML formatter: %v", err),
				Type:    "error",
			}
		}

		// Generate report
		if err := htmlFormatter.Generate(findings, enrichmentMap, metadata, outputFile); err != nil {
			return ShowMessageMsg{
				Title:   "Error",
				Message: fmt.Sprintf("Failed to generate report: %v", err),
				Type:    "error",
			}
		}

		return ShowMessageMsg{
			Title:   "Success",
			Message: fmt.Sprintf("Report generated: %s", outputFile),
			Type:    "success",
		}
	}
}

// enrichScan enriches findings for the given scan ID.
func (m *TUIModel) enrichScan(scanID int64) tea.Cmd {
	return func() tea.Msg {
		// TODO: Implement full enrichment functionality
		// This would involve:
		// 1. Loading findings from the scan
		// 2. Running AI enrichment
		// 3. Saving enrichments to database
		return ShowMessageMsg{
			Title:   "Finding Enrichment",
			Message: fmt.Sprintf("AI enrichment for scan %d started. This feature is coming soon!", scanID),
			Type:    "info",
		}
	}
}

// convertDBFindingToModel converts a database finding to a model finding.
func convertDBFindingToModel(dbFinding *database.Finding) models.Finding {
	finding := models.Finding{
		ID:          fmt.Sprintf("%d", dbFinding.ID),
		Scanner:     dbFinding.Scanner,
		Severity:    strings.ToLower(string(dbFinding.Severity)),
		Title:       dbFinding.Title,
		Description: dbFinding.Description,
		Resource:    dbFinding.Resource,
		Metadata:    make(map[string]string),
	}

	// Extract technical details
	if len(dbFinding.TechnicalDetails) > 0 {
		var details map[string]any
		if err := json.Unmarshal(dbFinding.TechnicalDetails, &details); err == nil {
			// Extract known fields
			if typ, ok := details["type"].(string); ok {
				finding.Type = typ
			}
			if rem, ok := details["remediation"].(string); ok {
				finding.Remediation = rem
			}

			// Extract business context
			if impact, ok := details["business_impact"].(string); ok {
				if finding.BusinessContext == nil {
					finding.BusinessContext = &models.BusinessContext{}
				}
				finding.BusinessContext.BusinessImpact = impact
			}
			if owner, ok := details["owner"].(string); ok {
				if finding.BusinessContext == nil {
					finding.BusinessContext = &models.BusinessContext{}
				}
				finding.BusinessContext.Owner = owner
			}

			// Add remaining fields to metadata
			for k, v := range details {
				if k != "type" && k != "remediation" && k != "business_impact" && k != "owner" {
					if strVal, ok := v.(string); ok {
						finding.Metadata[k] = strVal
					}
				}
			}
		}
	}

	return finding
}
