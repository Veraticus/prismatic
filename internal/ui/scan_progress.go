package ui

import (
	"context"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/joshsymonds/prismatic/internal/database"
	"github.com/joshsymonds/prismatic/internal/models"
)

// ScanProgress wraps the existing ScannerUI for use in the TUI.
type ScanProgress struct {
	lastDBUpdate time.Time
	scanner      *ScannerUI
	db           *database.DB
	currentScan  *database.Scan
	config       Config
	findingsBuf  []*models.Finding
	width        int
	height       int
}

// NewScanProgress creates a new scan progress page.
func NewScanProgress(clientName, environment, outputDir string) *ScanProgress {
	config := Config{
		StartTime:   time.Now(),
		OutputDir:   outputDir,
		ClientName:  clientName,
		Environment: environment,
	}

	return &ScanProgress{
		scanner: NewScannerUI(config),
		config:  config,
	}
}

// Init initializes the scan progress.
func (s *ScanProgress) Init() tea.Cmd {
	s.scanner.Start()
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg {
		return scannerTickMsg(t)
	})
}

// Update handles scan progress updates.
func (s *ScanProgress) Update(msg tea.Msg) (*ScanProgress, tea.Cmd) {
	switch msg := msg.(type) {
	case scannerTickMsg:
		// Check if we need to flush findings to database
		if s.db != nil && time.Since(s.lastDBUpdate) > 5*time.Second {
			if err := s.flushFindings(); err != nil {
				s.scanner.AddError("database", fmt.Sprintf("Failed to save findings: %v", err))
			}
			s.lastDBUpdate = time.Now()
		}

		// Continue ticking for UI updates
		return s, tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg {
			return scannerTickMsg(t)
		})

	case ScannerStatusMsg:
		// Update scanner status
		s.scanner.UpdateScanner(msg.Status)
		return s, nil

	case RepoStatusMsg:
		// Update repository status
		s.scanner.UpdateRepository(msg.Name, msg.Status, msg.LocalPath, msg.Error)
		return s, nil

	case ScannerErrorMsg:
		// Add error message
		s.scanner.AddError(msg.Scanner, msg.Message)
		return s, nil

	case FindingMsg:
		// Buffer finding for database insert
		if s.db != nil && msg.Finding != nil {
			s.findingsBuf = append(s.findingsBuf, msg.Finding)
			// Flush if buffer is getting large
			if len(s.findingsBuf) >= 100 {
				if err := s.flushFindings(); err != nil {
					s.scanner.AddError("database", fmt.Sprintf("Failed to save findings: %v", err))
				}
			}
		}
		return s, nil

	case ScanCompleteMsg:
		// Flush any remaining findings
		if s.db != nil {
			if err := s.flushFindings(); err != nil {
				s.scanner.AddError("database", fmt.Sprintf("Failed to save final findings: %v", err))
			}
			// Update scan status to completed
			if s.currentScan != nil {
				if err := s.db.UpdateScanStatus(context.Background(), s.currentScan.ID, database.ScanStatusCompleted, nil); err != nil {
					s.scanner.AddError("database", fmt.Sprintf("Failed to update scan status: %v", err))
				}
			}
		}
		// Render final state
		s.scanner.RenderFinalState(msg.Summary)
		return s, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			// TODO: Implement scan cancellation
			return s, nil
		}
	}

	return s, nil
}

// View renders the scan progress.
func (s *ScanProgress) View() string {
	// Get the rendered UI as a string
	rendered := s.scanner.Render()

	// Add navigation hint
	return rendered + "\n[Press Esc to go back]"
}

// SetSize updates the page dimensions.
func (s *ScanProgress) SetSize(width, height int) {
	s.width = width
	s.height = height
	if s.scanner != nil {
		s.scanner.updateBoxWidth()
	}
}

// Messages for scanner updates

type scannerTickMsg time.Time

// ScannerStatusMsg updates scanner status.
type ScannerStatusMsg struct {
	Status *models.ScannerStatus
}

// RepoStatusMsg updates repository status.
type RepoStatusMsg struct {
	Error     error
	Name      string
	Status    string
	LocalPath string
}

// ScannerErrorMsg adds an error message.
type ScannerErrorMsg struct {
	Scanner string
	Message string
}

// ScanCompleteMsg indicates scan completion.
type ScanCompleteMsg struct {
	Summary []string
}

// FindingMsg contains a finding to be saved.
type FindingMsg struct {
	Finding *models.Finding
}

// SetDatabase sets the database connection.
func (s *ScanProgress) SetDatabase(db *database.DB) {
	s.db = db
}

// SetScan sets the current scan record.
func (s *ScanProgress) SetScan(scan *database.Scan) {
	s.currentScan = scan
}

// flushFindings saves buffered findings to the database.
func (s *ScanProgress) flushFindings() error {
	if s.db == nil || s.currentScan == nil || len(s.findingsBuf) == 0 {
		return nil
	}

	ctx := context.Background()

	// Convert models.Finding to database.Finding
	dbFindings := make([]*database.Finding, 0, len(s.findingsBuf))
	for _, f := range s.findingsBuf {
		if f == nil {
			continue // Skip nil findings
		}
		// Map severity
		var severity database.Severity
		switch f.Severity {
		case models.SeverityCritical:
			severity = database.SeverityCritical
		case models.SeverityHigh:
			severity = database.SeverityHigh
		case models.SeverityMedium:
			severity = database.SeverityMedium
		case models.SeverityLow:
			severity = database.SeverityLow
		case models.SeverityInfo:
			severity = database.SeverityInfo
		default:
			severity = database.SeverityInfo
		}

		dbFinding := &database.Finding{
			ScanID:      s.currentScan.ID,
			Scanner:     f.Scanner,
			Severity:    severity,
			Title:       f.Title,
			Description: f.Description,
			Resource:    f.Resource,
			// Technical details would need to be marshaled from metadata
		}
		dbFindings = append(dbFindings, dbFinding)
	}

	// Insert findings in batch
	err := s.db.BatchInsertFindings(ctx, s.currentScan.ID, dbFindings)
	if err != nil {
		return fmt.Errorf("inserting findings: %w", err)
	}

	// Clear buffer
	s.findingsBuf = s.findingsBuf[:0]
	return nil
}
