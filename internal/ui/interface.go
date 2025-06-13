package ui

import (
	"github.com/joshsymonds/prismatic/internal/models"
)

// UI defines the interface for scanner UI implementations.
type UI interface {
	// Start begins the UI rendering loop
	Start()

	// Stop stops the UI rendering and restores terminal
	Stop()

	// UpdateRepository updates the status of a repository
	UpdateRepository(name, status, localPath string, err error)

	// UpdateScanner updates scanner status
	UpdateScanner(status *models.ScannerStatus)

	// AddError adds an error message to display
	AddError(scanner, message string)

	// IsStopped returns true if the UI has been stopped
	IsStopped() bool

	// RenderFinalState renders the UI one last time with the given summary
	RenderFinalState(summaryLines []string)
}