// Package main is the entry point for the Prismatic security scanner.
// Prismatic provides an interactive terminal UI for orchestrating multiple
// open-source security tools to perform comprehensive security assessments.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/joshsymonds/prismatic/internal/database"
	"github.com/joshsymonds/prismatic/internal/ui"
	"github.com/joshsymonds/prismatic/pkg/logger"

	// Import scanner implementations to register them.
	_ "github.com/joshsymonds/prismatic/internal/scanner/trivy"
)

var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	os.Exit(run())
}

func run() int {
	// Parse flags
	var (
		debug       bool
		logFormat   string
		showVersion bool
		help        bool
	)

	flag.BoolVar(&debug, "debug", false, "Enable debug logging")
	flag.StringVar(&logFormat, "log-format", "text", "Log format (text or json)")
	flag.BoolVar(&showVersion, "version", false, "Show version information")
	flag.BoolVar(&showVersion, "v", false, "Show version information (shorthand)")
	flag.BoolVar(&help, "help", false, "Show help message")
	flag.BoolVar(&help, "h", false, "Show help message (shorthand)")

	flag.Parse()

	if showVersion {
		// Version info should go to stdout, not logger
		if _, err := fmt.Fprintf(os.Stdout, "prismatic version %s (built %s)\n", version, buildTime); err != nil {
			// Failed to write version info
			return 1
		}
		return 0
	}

	if help {
		printUsage()
		return 0
	}

	// Setup logger
	logger.SetupLogger(debug, logFormat)

	// Create database connection
	db, err := database.New("prismatic.db")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating database: %v\n", err)
		return 1
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			logger.Error("Failed to close database", "error", closeErr)
		}
	}()

	// Launch TUI
	tui := ui.NewTUI(db)
	err = tui.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	return 0
}

func printUsage() {
	// Help information should go to stdout, not logger
	helpText := `🔍 Prismatic Security Scanner

Usage:
  prismatic [flags]

Prismatic provides an interactive terminal UI for comprehensive security scanning.

Flags:
  -h, --help         Show this help message
  -v, --version      Show version information
  --debug            Enable debug logging
  --log-format       Log format (text or json) (default: text)

Features:
  • Configure and run security scans
  • View scan history and results
  • Generate HTML/PDF reports
  • Enrich findings with AI analysis
  • All through an intuitive TUI interface

Example:
  prismatic          # Launch the interactive TUI
  prismatic --debug  # Launch with debug logging enabled`

	if _, err := fmt.Fprintln(os.Stdout, helpText); err != nil {
		// Failed to write help text, exit silently
		os.Exit(1)
	}
}
