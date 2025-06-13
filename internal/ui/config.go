package ui

import "time"

// Config contains configuration for the UI.
type Config struct {
	// OutputDir is the directory where scan results will be saved
	OutputDir string
	
	// ClientName is the name of the client being scanned
	ClientName string
	
	// Environment is the environment being scanned (e.g., production, staging)
	Environment string
	
	// StartTime is when the scan started
	StartTime time.Time
}