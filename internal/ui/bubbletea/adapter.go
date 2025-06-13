package bubbletea

import (
	"os"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/joshsymonds/prismatic/internal/ui"
)

// ScannerUIAdapter implements the UI interface using bubbletea.
type ScannerUIAdapter struct {
	program      *tea.Program
	model        *Model
	tickerCancel chan bool
	stopOnce     sync.Once
	mu           sync.Mutex
	stopped      bool
}

// NewScannerUIAdapter creates a new adapter that implements the UI interface.
func NewScannerUIAdapter(config ui.Config) *ScannerUIAdapter {
	model := &Model{
		startTime:    config.StartTime,
		outputDir:    config.OutputDir,
		client:       config.ClientName,
		environment:  config.Environment,
		repos:        []RepoState{},
		repoIndex:    make(map[string]int),
		scanners:     []ScannerState{},
		scannerIndex: make(map[string]int),
		errors:       NewRingBuffer[ErrorEntry](5), // Keep last 5 errors
		updates:      make(chan Msg, 100),
		infoMaxHeight: 10, // Limit info section to 10 lines
	}

	// Create program but don't start it yet
	opts := []tea.ProgramOption{
		tea.WithAltScreen(),       // Use alternate screen buffer
		tea.WithMouseCellMotion(), // Enable mouse support
	}

	// In test environments, use a nil input/output to avoid terminal interaction
	if os.Getenv("GO_TEST") == "true" || os.Getenv("CI") == "true" {
		opts = append(opts, tea.WithInput(nil), tea.WithoutRenderer())
	}

	program := tea.NewProgram(model, opts...)

	return &ScannerUIAdapter{
		program:      program,
		model:        model,
		tickerCancel: make(chan bool),
	}
}

// Start begins the UI rendering loop.
func (a *ScannerUIAdapter) Start() {
	// In test environments, don't actually start the program
	if os.Getenv("GO_TEST") == "true" || os.Getenv("CI") == "true" {
		return
	}

	// Start the bubbletea program in a goroutine
	go func() {
		if _, err := a.program.Run(); err != nil {
			// Handle error silently
			return
		}
	}()

	// Give the program a moment to initialize
	time.Sleep(50 * time.Millisecond)

	// Start ticker for duration updates
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				a.program.Send(TickMsg(time.Now()))
			case <-a.tickerCancel:
				return
			}
		}
	}()
}

// Stop stops the UI rendering and restores terminal.
func (a *ScannerUIAdapter) Stop() {
	a.stopOnce.Do(func() {
		a.mu.Lock()
		a.stopped = true
		a.mu.Unlock()

		// Stop the ticker
		select {
		case <-a.tickerCancel:
			// Already closed
		default:
			close(a.tickerCancel)
		}

		// Send quit message to the program if it's running
		if a.program != nil {
			a.program.Send(tea.Quit())
		}
	})
}

// UpdateRepository updates the status of a repository.
func (a *ScannerUIAdapter) UpdateRepository(name, status, localPath string, err error) {
	if a.isStopped() {
		return
	}

	// In test mode, update the model directly
	if os.Getenv("GO_TEST") == "true" || os.Getenv("CI") == "true" {
		msg := RepoStatusMsg{
			Name:      name,
			Status:    ParseRepoStatus(status),
			LocalPath: localPath,
			Error:     err,
		}
		a.model.updateRepo(msg)
		return
	}

	a.program.Send(RepoStatusMsg{
		Name:      name,
		Status:    ParseRepoStatus(status),
		LocalPath: localPath,
		Error:     err,
	})
}

// UpdateScanner updates scanner status.
func (a *ScannerUIAdapter) UpdateScanner(status *models.ScannerStatus) {
	if a.isStopped() {
		return
	}

	// In test mode, update the model directly
	if os.Getenv("GO_TEST") == "true" || os.Getenv("CI") == "true" {
		msg := ScannerStatusMsg{
			Scanner: status.Scanner,
			Status:  status,
		}
		a.model.updateScanner(msg)
		return
	}

	a.program.Send(ScannerStatusMsg{
		Scanner: status.Scanner,
		Status:  status,
	})
}

// AddError adds an error message to display.
func (a *ScannerUIAdapter) AddError(scanner, message string) {
	if a.isStopped() {
		return
	}

	// In test mode, update the model directly
	if os.Getenv("GO_TEST") == "true" || os.Getenv("CI") == "true" {
		a.model.addError(scanner, message)
		return
	}

	a.program.Send(ScannerErrorMsg{
		Scanner: scanner,
		Error:   message,
	})
}

// IsStopped returns true if the UI has been stopped.
func (a *ScannerUIAdapter) IsStopped() bool {
	return a.isStopped()
}

// RenderFinalState renders the UI one last time with the given summary and keeps it visible.
func (a *ScannerUIAdapter) RenderFinalState(summaryLines []string) {
	// In test mode, update the model directly
	if os.Getenv("GO_TEST") == "true" || os.Getenv("CI") == "true" {
		a.model.showFinalSummary = true
		a.model.finalMessage = summaryLines
		return
	}

	// Send the final summary message which will trigger a quit
	a.program.Send(FinalSummaryMsg{Lines: summaryLines})

	// Wait for the program to render the final state
	time.Sleep(200 * time.Millisecond)

	// The program will quit after rendering the final state
	// due to the tea.Quit command in the Update function
}

// isStopped is an internal helper to check stopped state with mutex.
func (a *ScannerUIAdapter) isStopped() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.stopped
}
