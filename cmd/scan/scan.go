// Package scan implements the scan command for Prismatic security scanner.
package scan

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/joshsymonds/prismatic/internal/config"
	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/joshsymonds/prismatic/internal/scanner"
	"github.com/joshsymonds/prismatic/internal/storage"
	"github.com/joshsymonds/prismatic/internal/ui"
	"github.com/joshsymonds/prismatic/pkg/logger"
)

// Options represents scan command options.
type Options struct {
	ConfigFile   string
	OutputDir    string
	AWSProfile   string
	K8sContext   string
	OnlyScanners []string
	Timeout      int
	Mock         bool
}

// Run executes the scan command.
func Run(args []string) error {
	opts := &Options{}

	// Parse command flags
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	fs.StringVar(&opts.ConfigFile, "config", "", "Configuration file path (required)")
	fs.StringVar(&opts.OutputDir, "output", "", "Output directory for scan results")
	fs.StringVar(&opts.AWSProfile, "aws-profile", "", "AWS profile to use")
	fs.StringVar(&opts.K8sContext, "k8s-context", "", "Kubernetes context to use")
	fs.IntVar(&opts.Timeout, "timeout", 1800, "Timeout in seconds per scanner")
	fs.BoolVar(&opts.Mock, "mock", false, "Use mock scanners for testing")

	// Handle --only flag
	var onlyFlag string
	fs.StringVar(&onlyFlag, "only", "", "Only run specific scanners (comma-separated)")

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `Usage: prismatic scan [options]

Run security scans based on configuration file.

Options:`)
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, `
Examples:
  prismatic scan --config client-acme.yaml
  prismatic scan --config client.yaml --only aws,docker
  prismatic scan --config client.yaml --output data/scans/manual-scan
  prismatic scan --mock --config test.yaml`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Validate required flags
	if opts.ConfigFile == "" {
		return fmt.Errorf("--config flag is required")
	}

	// Parse only scanners
	if onlyFlag != "" {
		opts.OnlyScanners = strings.Split(onlyFlag, ",")
		for i, s := range opts.OnlyScanners {
			opts.OnlyScanners[i] = strings.TrimSpace(s)
		}
	}

	// Generate output directory if not specified
	if opts.OutputDir == "" {
		timestamp := time.Now().Format("2006-01-02-150405")
		opts.OutputDir = filepath.Join("data", "scans", timestamp)
	}

	// Load configuration
	cfg, err := config.LoadConfig(opts.ConfigFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Create and start UI
	ui := createScannerUI(cfg, opts)
	ui.Start()
	defer ui.Stop()

	// Create log file for debugging
	logFile, err := createLogFile(opts.OutputDir)
	if err != nil {
		logger.Warn("Failed to create log file", "error", err)
	} else {
		defer func() {
			if closeErr := logFile.Close(); closeErr != nil {
				logger.Warn("Failed to close log file", "error", closeErr)
			}
		}()
	}

	// Create scan context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(opts.Timeout)*time.Second)
	defer cancel()

	// Initialize orchestrator with UI-aware logger that also logs to file
	scanLogger := &uiLogger{ui: ui, logFile: logFile}
	orchestrator := scanner.NewOrchestratorWithLogger(cfg, opts.OutputDir, opts.Mock, scanLogger)

	// Set the timeout from command line flag
	orchestrator.SetScanTimeout(time.Duration(opts.Timeout) * time.Second)

	// Prepare repositories if configured
	if len(cfg.Repositories) > 0 {
		// Initialize repository status in UI
		for _, repo := range cfg.Repositories {
			ui.UpdateRepository(repo.Name, "pending", "", nil)
		}

		// Hook into repository preparation
		prepErr := prepareRepositoriesWithUI(ctx, orchestrator, ui, cfg.Repositories)
		if prepErr != nil {
			ui.AddError("repository", prepErr.Error())
			time.Sleep(2 * time.Second) // Let user see the error
			return fmt.Errorf("preparing repositories: %w", prepErr)
		}
		defer orchestrator.CleanupRepositories()
	}

	// Initialize scanners
	if initErr := orchestrator.InitializeScanners(opts.OnlyScanners); initErr != nil {
		ui.AddError("init", initErr.Error())
		time.Sleep(2 * time.Second) // Let user see the error
		return fmt.Errorf("initializing scanners: %w", initErr)
	}

	// Set up status channel for real-time updates
	statusChan := make(chan *models.ScannerStatus, 100)
	orchestrator.SetStatusChannel(statusChan)

	// Start status monitor
	statusDone := make(chan bool)
	go func() {
		defer func() { statusDone <- true }()
		for status := range statusChan {
			ui.UpdateScanner(status)

			// Capture error messages
			if status.Status == models.StatusFailed && status.Message != "" {
				ui.AddError(status.Scanner, status.Message)
			}
		}
	}()

	// Run scans
	metadata, err := orchestrator.RunScans(ctx)

	// Signal status monitor to stop
	close(statusChan)
	<-statusDone

	if err != nil {
		ui.AddError("scan", err.Error())
		time.Sleep(2 * time.Second) // Let user see the error
		return fmt.Errorf("running scans: %w", err)
	}

	// Set additional metadata
	metadata.ID = filepath.Base(opts.OutputDir)
	metadata.ConfigFile = opts.ConfigFile

	// Save results
	store := storage.NewStorage("data")
	if err := store.SaveScanResults(opts.OutputDir, metadata); err != nil {
		ui.AddError("save", err.Error())
		time.Sleep(2 * time.Second) // Let user see the error
		return fmt.Errorf("saving results: %w", err)
	}

	// Final render before exit
	time.Sleep(1 * time.Second)

	// Build summary lines for the final UI render
	summaryLines := buildScanSummaryLines(metadata, opts)

	// Render final state with summary
	ui.RenderFinalState(summaryLines)

	// Stop the UI (this just stops the rendering loop)
	ui.Stop()

	return nil
}

// createScannerUI creates and configures the scanner UI.
func createScannerUI(cfg *config.Config, opts *Options) *ui.ScannerUI {
	return ui.NewScannerUI(ui.Config{
		OutputDir:   opts.OutputDir,
		ClientName:  cfg.Client.Name,
		Environment: cfg.Client.Environment,
		StartTime:   time.Now(),
	})
}

// uiLogger implements the logger interface and redirects to the UI and log file.
type uiLogger struct {
	ui      *ui.ScannerUI
	logFile *os.File
}

func (l *uiLogger) Debug(msg string, fields ...any) {
	// Write debug to file only
	l.writeToFile("DEBUG", msg, fields)
}

func (l *uiLogger) Info(msg string, fields ...any) {
	// Always write to file
	l.writeToFile("INFO", msg, fields)

	// Handle repository status updates
	switch msg {
	case "Cloning repository":
		name := l.extractField(fields, "name")
		if name != "" {
			l.ui.UpdateRepository(name, "cloning", "", nil)
		}
	case "Repository prepared":
		name := l.extractField(fields, "name")
		path := l.extractField(fields, "local_path")
		if name != "" {
			l.ui.UpdateRepository(name, "complete", path, nil)
		}
	default:
		// Show important Nuclei debugging info
		if strings.Contains(msg, "Nuclei") || strings.Contains(msg, "nuclei") {
			l.ui.AddError("nuclei", fmt.Sprintf("%s %v", msg, fields))
		} else if strings.Contains(msg, "error") || strings.Contains(msg, "failed") {
			l.ui.AddError("info", fmt.Sprintf("%s %v", msg, fields))
		}
	}
}

func (l *uiLogger) Warn(msg string, fields ...any) {
	l.writeToFile("WARN", msg, fields)
	l.ui.AddError("warn", fmt.Sprintf("%s %v", msg, fields))
}

func (l *uiLogger) Error(msg string, fields ...any) {
	l.writeToFile("ERROR", msg, fields)

	// Handle repository clone failures
	if msg == "Repository clone failed" {
		name := l.extractField(fields, "name")
		errMsg := l.extractField(fields, "error")
		if name != "" {
			l.ui.UpdateRepository(name, "failed", "", fmt.Errorf("%s", errMsg))
		}
	}
	l.ui.AddError("error", fmt.Sprintf("%s %v", msg, fields))
}

// With creates a new logger with additional context fields.
func (l *uiLogger) With(_ ...any) logger.Logger {
	// Return the same logger since we don't need context fields for UI
	return l
}

// WithGroup creates a new logger with a group name.
func (l *uiLogger) WithGroup(_ string) logger.Logger {
	// Return the same logger since we don't need groups for UI
	return l
}

// extractField extracts a field value from logger fields.
func (l *uiLogger) extractField(fields []any, key string) string {
	for i := 0; i < len(fields)-1; i += 2 {
		if fields[i] == key {
			if val, ok := fields[i+1].(string); ok {
				return val
			}
			return fmt.Sprintf("%v", fields[i+1])
		}
	}
	return ""
}

// prepareRepositoriesWithUI prepares repositories with UI updates.
func prepareRepositoriesWithUI(ctx context.Context, orchestrator *scanner.Orchestrator, _ *ui.ScannerUI, _ []config.Repository) error {
	// The UI updates are handled through the logger callbacks
	return orchestrator.PrepareRepositories(ctx)
}

func buildScanSummaryLines(_ *models.ScanMetadata, opts *Options) []string {
	return []string{
		fmt.Sprintf("📁 Results saved to: %s", opts.OutputDir),
		"🎯 Run 'prismatic report --scan latest' to generate report",
	}
}

// createLogFile creates a log file in the output directory.
func createLogFile(outputDir string) (*os.File, error) {
	// Ensure output directory exists
	if err := os.MkdirAll(outputDir, 0750); err != nil {
		return nil, fmt.Errorf("creating output directory: %w", err)
	}

	logPath := filepath.Join(outputDir, "prismatic.log")
	file, err := os.Create(filepath.Clean(logPath))
	if err != nil {
		return nil, fmt.Errorf("creating log file: %w", err)
	}

	// Write header
	_, _ = fmt.Fprintf(file, "=== Prismatic Security Scanner Log ===\n")
	_, _ = fmt.Fprintf(file, "Started at: %s\n", time.Now().Format(time.RFC3339))
	_, _ = fmt.Fprintf(file, "Output directory: %s\n", outputDir)
	_, _ = fmt.Fprintf(file, "=====================================\n\n")

	return file, nil
}

// writeToFile writes a log entry to the file.
func (l *uiLogger) writeToFile(level, msg string, fields []any) {
	if l.logFile == nil {
		return
	}

	timestamp := time.Now().Format("15:04:05.000")

	// Format fields
	fieldStr := ""
	for i := 0; i < len(fields); i += 2 {
		if i+1 < len(fields) {
			if fieldStr != "" {
				fieldStr += " "
			}
			fieldStr += fmt.Sprintf("%v=%v", fields[i], fields[i+1])
		}
	}

	// Write log entry
	logEntry := fmt.Sprintf("[%s] %s: %s", timestamp, level, msg)
	if fieldStr != "" {
		logEntry += " " + fieldStr
	}
	logEntry += "\n"

	_, _ = l.logFile.WriteString(logEntry)
}
