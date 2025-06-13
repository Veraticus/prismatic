package bubbletea

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/joshsymonds/prismatic/internal/models"
)

// Msg is the base interface for all messages.
type Msg interface{}

// Repository messages

// RepoStatusMsg updates repository status.
type RepoStatusMsg struct {
	Error     error
	Name      string
	Status    RepoStatus
	LocalPath string
}

// Scanner messages

// ScannerStatusMsg updates scanner status.
type ScannerStatusMsg struct {
	Status  *models.ScannerStatus
	Scanner string
}

// ScannerErrorMsg reports a scanner error.
type ScannerErrorMsg struct {
	Scanner string
	Error   string
}

// Lifecycle messages

// FinalSummaryMsg displays the final summary and exits.
type FinalSummaryMsg struct {
	Lines []string
}

// Internal messages

// WindowSizeMsg updates terminal dimensions.
type WindowSizeMsg struct {
	Width  int
	Height int
}

// TickMsg is sent periodically to update durations.
type TickMsg time.Time

// Helper functions to convert status types

// ParseRepoStatus converts string status to typed enum.
func ParseRepoStatus(status string) RepoStatus {
	switch status {
	case "pending":
		return RepoStatusPending
	case "cloning":
		return RepoStatusCloning
	case "complete":
		return RepoStatusReady
	case "failed":
		return RepoStatusFailed
	default:
		return RepoStatusPending
	}
}

// ParseScannerStatus converts models.Status* constants to typed enum.
func ParseScannerStatus(status string) ScannerStatus {
	switch status {
	case models.StatusPending:
		return ScannerStatusPending
	case models.StatusStarting:
		return ScannerStatusStarting
	case models.StatusRunning:
		return ScannerStatusRunning
	case models.StatusSuccess:
		return ScannerStatusSuccess
	case models.StatusFailed:
		return ScannerStatusFailed
	case models.StatusSkipped:
		return ScannerStatusSkipped
	default:
		return ScannerStatusPending
	}
}

// Update handles all incoming messages and updates the model accordingly.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case RepoStatusMsg:
		m.updateRepo(msg)
		return m, nil

	case ScannerStatusMsg:
		m.updateScanner(msg)
		return m, nil

	case ScannerErrorMsg:
		m.addError(msg.Scanner, msg.Error)
		return m, nil

	case FinalSummaryMsg:
		m.showFinalSummary = true
		m.finalMessage = msg.Lines
		// Return tea.Quit but view will render one final time
		return m, tea.Quit

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC:
			m.stopped = true
			return m, tea.Quit
		case tea.KeyUp, tea.KeyCtrlP: // Up arrow or Ctrl+P
			if m.infoScrollOffset > 0 {
				m.infoScrollOffset--
			}
			return m, nil
		case tea.KeyDown, tea.KeyCtrlN: // Down arrow or Ctrl+N
			m.infoScrollOffset++
			return m, nil
		case tea.KeyHome:
			m.infoScrollOffset = 0
			return m, nil
		case tea.KeyPgUp:
			m.infoScrollOffset -= m.infoMaxHeight / 2
			if m.infoScrollOffset < 0 {
				m.infoScrollOffset = 0
			}
			return m, nil
		case tea.KeyPgDown:
			m.infoScrollOffset += m.infoMaxHeight / 2
			return m, nil
		}
		
		// Handle vim keys and other single key commands
		switch msg.String() {
		case "q", "Q": // Quit
			m.stopped = true
			return m, tea.Quit
		case "k": // Vim up
			if m.infoScrollOffset > 0 {
				m.infoScrollOffset--
			}
			return m, nil
		case "j": // Vim down
			m.infoScrollOffset++
			return m, nil
		case "g": // Vim go to top
			m.infoScrollOffset = 0
			return m, nil
		case "G": // Vim go to bottom
			// Will be adjusted in render based on actual content
			m.infoScrollOffset = 999999
			return m, nil
		}

	case TickMsg:
		// Update durations for running scanners
		m.updateElapsedTimes()
		return m, tickCmd()
	}

	return m, nil
}
