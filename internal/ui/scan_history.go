package ui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/joshsymonds/prismatic/internal/database"
)

// ScanHistoryItem represents a past scan with additional display information.
type ScanHistoryItem struct {
	Scan          *database.Scan
	FindingCounts *database.FindingCounts
}

// ScanHistory represents the scan history page.
type ScanHistory struct {
	db       *database.DB
	errorMsg string
	scans    []ScanHistoryItem
	cursor   int
	width    int
	height   int
	loading  bool
}

// NewScanHistory creates a new scan history page.
func NewScanHistory() *ScanHistory {
	return &ScanHistory{
		scans:   []ScanHistoryItem{},
		cursor:  0,
		loading: false, // Don't load until database is set
	}
}

// LoadScansMsg is sent when scans are loaded from the database.
type LoadScansMsg struct {
	Err   error
	Scans []ScanHistoryItem
}

// Init initializes the scan history.
func (s *ScanHistory) Init() tea.Cmd {
	if s.db != nil {
		s.loading = true
		return s.loadScans
	}
	return nil
}

// loadScans loads scan history from the database.
func (s *ScanHistory) loadScans() tea.Msg {
	if s.db == nil {
		return LoadScansMsg{Err: fmt.Errorf("database not initialized")}
	}

	ctx := context.Background()

	// Load all scans, ordered by most recent first
	filter := database.ScanFilter{
		Limit:  100, // Reasonable limit for UI display
		Offset: 0,
	}

	scans, err := s.db.ListScans(ctx, filter)
	if err != nil {
		return LoadScansMsg{Err: fmt.Errorf("loading scans: %w", err)}
	}

	// Load finding counts for each scan
	items := make([]ScanHistoryItem, 0, len(scans))
	for _, scan := range scans {
		counts, err := s.db.GetFindingCounts(ctx, scan.ID)
		if err != nil {
			// Log error but continue - scan might not have findings yet
			counts = &database.FindingCounts{}
		}
		items = append(items, ScanHistoryItem{
			Scan:          scan,
			FindingCounts: counts,
		})
	}

	return LoadScansMsg{Scans: items}
}

// Update handles scan history updates.
func (s *ScanHistory) Update(msg tea.Msg) (*ScanHistory, tea.Cmd) {
	switch msg := msg.(type) {
	case LoadScansMsg:
		s.loading = false
		if msg.Err != nil {
			s.errorMsg = msg.Err.Error()
		} else {
			s.scans = msg.Scans
			if len(s.scans) > 0 && s.cursor >= len(s.scans) {
				s.cursor = len(s.scans) - 1
			}
		}
		return s, nil

	case tea.KeyMsg:
		if s.loading {
			return s, nil // Ignore keys while loading
		}

		switch msg.String() {
		case "j", "down":
			if s.cursor < len(s.scans)-1 {
				s.cursor++
			}
		case "k", "up":
			if s.cursor > 0 {
				s.cursor--
			}
		case "g":
			s.cursor = 0
		case "G":
			if len(s.scans) > 0 {
				s.cursor = len(s.scans) - 1
			}
		case "enter":
			if s.cursor < len(s.scans) {
				// TODO: Load selected scan results
				return s, func() tea.Msg {
					return NavigateToPageMsg{Page: ResultsBrowserPage}
				}
			}
		case "d":
			// TODO: Delete scan (with confirmation)
		case "r":
			// Generate report for scan
			if s.cursor < len(s.scans) {
				return s, func() tea.Msg {
					return GenerateReportMsg{ScanID: s.scans[s.cursor].Scan.ID}
				}
			}
		case "e":
			// Enrich findings for scan
			if s.cursor < len(s.scans) {
				return s, func() tea.Msg {
					return EnrichScanMsg{ScanID: s.scans[s.cursor].Scan.ID}
				}
			}
		case "R":
			// Refresh scan list
			s.loading = true
			return s, s.loadScans
		}
	}
	return s, nil
}

// View renders the scan history.
func (s *ScanHistory) View() string {
	var b strings.Builder

	// Title
	title := TitleStyle.Render("Scan History")
	b.WriteString(lipgloss.PlaceHorizontal(s.width, lipgloss.Center, title))
	b.WriteString("\n\n")

	switch {
	case s.loading:
		b.WriteString(lipgloss.PlaceHorizontal(s.width, lipgloss.Center, "Loading scans..."))
	case s.errorMsg != "":
		errorStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000"))
		b.WriteString(lipgloss.PlaceHorizontal(s.width, lipgloss.Center, errorStyle.Render("Error: "+s.errorMsg)))
	case len(s.scans) == 0:
		b.WriteString(lipgloss.PlaceHorizontal(s.width, lipgloss.Center, "No previous scans found"))
	default:
		// Table header
		headerStyle := lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00FFFF")).
			BorderBottom(true).
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("#333333"))

		headers := []string{
			s.padRight("Client", 15),
			s.padRight("Environment", 12),
			s.padRight("Date", 20),
			s.padRight("Duration", 10),
			s.padRight("Findings", 10),
			s.padRight("Status", 10),
		}

		b.WriteString("  ")
		b.WriteString(headerStyle.Render(strings.Join(headers, " ")))
		b.WriteString("\n\n")

		// Scan rows
		for i, item := range s.scans {
			cursor := "  "
			style := NormalItemStyle

			if s.cursor == i {
				cursor = "▸ "
				style = SelectedItemStyle
			}

			// Extract client name and environment from scan metadata
			// For now, use scan ID and profile as placeholders
			clientName := fmt.Sprintf("scan-%d", item.Scan.ID)
			if item.Scan.AWSProfile.Valid {
				clientName = item.Scan.AWSProfile.String
			}
			environment := "unknown"
			if item.Scan.KubeContext.Valid {
				environment = item.Scan.KubeContext.String
			}

			// Calculate duration
			var duration time.Duration
			if item.Scan.CompletedAt.Valid {
				duration = item.Scan.CompletedAt.Time.Sub(item.Scan.StartedAt).Round(time.Minute)
			} else {
				duration = time.Since(item.Scan.StartedAt).Round(time.Minute)
			}

			// Status display
			statusDisplay := string(item.Scan.Status)
			switch item.Scan.Status {
			case database.ScanStatusRunning:
				statusDisplay = "Running"
			case database.ScanStatusCompleted:
				statusDisplay = "Completed"
			case database.ScanStatusFailed:
				statusDisplay = "Failed"
			}

			row := fmt.Sprintf("%s%s %s %s %s %s %s",
				cursor,
				s.padRight(clientName, 15),
				s.padRight(environment, 12),
				s.padRight(item.Scan.StartedAt.Format("2006-01-02 15:04"), 20),
				s.padRight(duration.String(), 10),
				s.padRight(fmt.Sprintf("%d", item.FindingCounts.Total), 10),
				s.padRight(statusDisplay, 10),
			)

			b.WriteString(style.Render(row))
			b.WriteString("\n")
		}
	}

	// Help
	b.WriteString("\n\n")
	help := HelpStyle.Render("Navigate: j/k • View: Enter • Delete: d • Report: r • Enrich: e • Refresh: R • Back: Esc")
	b.WriteString(lipgloss.PlaceHorizontal(s.width, lipgloss.Center, help))

	return b.String()
}

// SetSize updates the page dimensions.
func (s *ScanHistory) SetSize(width, height int) {
	s.width = width
	s.height = height
}

// SetDatabase sets the database connection.
func (s *ScanHistory) SetDatabase(db *database.DB) {
	s.db = db
}

// padRight pads a string to the right with spaces.
func (s *ScanHistory) padRight(str string, length int) string {
	if len(str) >= length {
		return str[:length-1] + "…"
	}
	return str + strings.Repeat(" ", length-len(str))
}
