package bubbletea

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// Model represents the entire UI state for the scanner.
type Model struct {
	startTime        time.Time
	repoIndex        map[string]int
	updates          chan Msg
	errors           *RingBuffer[ErrorEntry]
	scannerIndex     map[string]int
	outputDir        string
	environment      string
	client           string
	repos            []RepoState
	scanners         []ScannerState
	finalMessage     []string
	width            int
	height           int
	showFinalSummary bool
	stopped          bool
	
	// Scrolling state for info section
	infoScrollOffset int
	infoMaxHeight    int // Maximum height for info section (in lines)
}

// RepoState represents the state of a repository.
type RepoState struct {
	UpdatedAt time.Time
	Name      string
	Status    RepoStatus
	LocalPath string
	Error     string
}

// RepoStatus represents the status of a repository.
type RepoStatus string

// Repository status constants.
const (
	RepoStatusPending RepoStatus = "pending"
	RepoStatusCloning RepoStatus = "cloning"
	RepoStatusReady   RepoStatus = "ready"
	RepoStatusFailed  RepoStatus = "failed"
)

// ScannerState represents the state of a scanner.
type ScannerState struct {
	StartTime time.Time
	UpdatedAt time.Time
	Findings  FindingSummary
	Name      string
	Status    ScannerStatus
	Message   string
	Progress  Progress
	Duration  time.Duration
}

// ScannerStatus represents the status of a scanner.
type ScannerStatus string

// Scanner status constants.
const (
	ScannerStatusPending  ScannerStatus = "pending"
	ScannerStatusStarting ScannerStatus = "starting"
	ScannerStatusRunning  ScannerStatus = "running"
	ScannerStatusSuccess  ScannerStatus = "success"
	ScannerStatusFailed   ScannerStatus = "failed"
	ScannerStatusSkipped  ScannerStatus = "skipped"
)

// Progress represents scanner progress information.
type Progress struct {
	Current int
	Total   int
	Percent int
}

// FindingSummary represents findings by severity.
type FindingSummary struct {
	BySeverity map[string]int
	Total      int
}

// ErrorEntry represents an error log entry.
type ErrorEntry struct {
	Timestamp time.Time
	Scanner   string
	Message   string
}

// Init initializes the model.
func (m Model) Init() tea.Cmd {
	// Start with a tick command for updating durations
	return tickCmd()
}

// tickCmd returns a command that sends a tick message.
func tickCmd() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

// updateElapsedTimes updates durations for running scanners.
func (m *Model) updateElapsedTimes() {
	now := time.Now()
	for i := range m.scanners {
		if m.scanners[i].Status == ScannerStatusRunning || m.scanners[i].Status == ScannerStatusStarting {
			m.scanners[i].Duration = now.Sub(m.scanners[i].StartTime)
		}
	}
}

// updateRepo updates repository state.
func (m *Model) updateRepo(msg RepoStatusMsg) {
	idx, exists := m.repoIndex[msg.Name]
	if !exists {
		// Add new repo
		idx = len(m.repos)
		m.repos = append(m.repos, RepoState{
			Name: msg.Name,
		})
		m.repoIndex[msg.Name] = idx
	}

	// Update repo state
	m.repos[idx].Status = msg.Status
	m.repos[idx].LocalPath = msg.LocalPath
	if msg.Error != nil {
		m.repos[idx].Error = msg.Error.Error()
		m.repos[idx].Status = RepoStatusFailed
	}
	m.repos[idx].UpdatedAt = time.Now()
}

// updateScanner updates scanner state.
func (m *Model) updateScanner(msg ScannerStatusMsg) {
	idx, exists := m.scannerIndex[msg.Scanner]
	if !exists {
		// Add new scanner
		idx = len(m.scanners)
		m.scanners = append(m.scanners, ScannerState{
			Name:      msg.Scanner,
			StartTime: time.Now(),
		})
		m.scannerIndex[msg.Scanner] = idx
	}

	// Update scanner state
	scanner := &m.scanners[idx]
	scanner.UpdatedAt = time.Now()

	if msg.Status != nil {
		// Convert status string to ScannerStatus
		scanner.Status = ScannerStatus(msg.Status.Status)
		scanner.Message = msg.Status.Message

		// Update progress
		if msg.Status.Total > 0 {
			scanner.Progress = Progress{
				Current: msg.Status.Current,
				Total:   msg.Status.Total,
				Percent: (msg.Status.Current * 100) / msg.Status.Total,
			}
		}

		// Update findings
		if msg.Status.TotalFindings > 0 || msg.Status.FindingCounts != nil {
			scanner.Findings = FindingSummary{
				Total:      msg.Status.TotalFindings,
				BySeverity: msg.Status.FindingCounts,
			}
		}

		// Update duration
		if scanner.Status == ScannerStatusSuccess || scanner.Status == ScannerStatusFailed || scanner.Status == ScannerStatusSkipped {
			scanner.Duration = time.Since(scanner.StartTime)
		}
	}
}

// addError adds an error to the error ring buffer.
func (m *Model) addError(scanner, message string) {
	m.errors.Add(ErrorEntry{
		Scanner:   scanner,
		Message:   message,
		Timestamp: time.Now(),
	})
}
