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

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/Veraticus/prismatic/internal/config"
	"github.com/Veraticus/prismatic/internal/models"
	"github.com/Veraticus/prismatic/internal/scanner"
	"github.com/Veraticus/prismatic/internal/storage"
	"github.com/Veraticus/prismatic/internal/ui"
	"github.com/Veraticus/prismatic/pkg/logger"
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
	fs.IntVar(&opts.Timeout, "timeout", 600, "Timeout in seconds per scanner")
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

	// Create scan context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(opts.Timeout)*time.Second)
	defer cancel()

	// Initialize orchestrator with UI-aware logger
	orchestrator := scanner.NewOrchestratorWithLogger(cfg, opts.OutputDir, opts.Mock, &uiLogger{ui: ui})

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

	// Print scan summary after UI is stopped
	ui.Stop()
	printScanSummary(metadata, opts)

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

// uiLogger implements the logger interface and redirects to the UI.
type uiLogger struct {
	ui *ui.ScannerUI
}

func (l *uiLogger) Debug(_ string, _ ...any) {
	// Ignore debug messages in UI mode
}

func (l *uiLogger) Info(msg string, fields ...any) {
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
		if strings.Contains(msg, "Nuclei") {
			l.ui.AddError("nuclei", fmt.Sprintf("%s %v", msg, fields))
		} else if strings.Contains(msg, "error") || strings.Contains(msg, "failed") {
			l.ui.AddError("info", fmt.Sprintf("%s %v", msg, fields))
		}
	}
}

func (l *uiLogger) Warn(msg string, fields ...any) {
	l.ui.AddError("warn", fmt.Sprintf("%s %v", msg, fields))
}

func (l *uiLogger) Error(msg string, fields ...any) {
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

func printScanSummary(metadata *models.ScanMetadata, opts *Options) {
	logger.Info("🔍 Prismatic Security Scanner v1.0.0")
	logger.Info("📋 Configuration: " + opts.ConfigFile)
	logger.Info("📁 Output: " + opts.OutputDir)

	if opts.Mock {
		logger.Info("⚠️  Running in MOCK mode - no real scans performed")
	}

	// Print scanner results
	logger.Info("📊 Scanner Results:")
	for i, scannerName := range metadata.Scanners {
		result, ok := metadata.Results[scannerName]
		if !ok {
			continue
		}

		status := "✅"
		statusMsg := fmt.Sprintf("%d findings", len(result.Findings))
		if result.Error != "" {
			status = "❌"
			statusMsg = "failed"
		}

		severityCounts := make(map[string]int)
		for _, finding := range result.Findings {
			if !finding.Suppressed {
				severityCounts[finding.Severity]++
			}
		}

		logger.Info(fmt.Sprintf("[%d/%d] %s %s...", i+1, len(metadata.Scanners), status, scannerName))
		logger.Info("      ⏱  " + result.EndTime.Sub(result.StartTime).Round(time.Millisecond).String())

		if result.Error == "" && len(result.Findings) > 0 {
			criticalHigh := severityCounts["critical"] + severityCounts["high"]
			if criticalHigh > 0 {
				logger.Info(fmt.Sprintf("      🚨 %d findings (%d critical/high)", len(result.Findings), criticalHigh))
			} else {
				logger.Info("      ✨ " + statusMsg)
			}
		} else if result.Error != "" {
			logger.Info("      ❗ " + result.Error)
		}
	}

	// Print overall summary
	logger.Info("✅ Scan Summary:")
	if metadata.Summary.SuppressedCount > 0 {
		logger.Info(fmt.Sprintf("   Total Findings: %d (+ %d suppressed)", metadata.Summary.TotalFindings, metadata.Summary.SuppressedCount))
	} else {
		logger.Info(fmt.Sprintf("   Total Findings: %d", metadata.Summary.TotalFindings))
	}

	// Print severity breakdown
	severityOrder := []string{"critical", "high", "medium", "low"}
	severityDisplay := []string{}
	for _, sev := range severityOrder {
		if count, ok := metadata.Summary.BySeverity[sev]; ok && count > 0 {
			severityDisplay = append(severityDisplay, fmt.Sprintf("%s: %d", cases.Title(language.English).String(sev), count))
		}
	}
	if len(severityDisplay) > 0 {
		logger.Info("   " + strings.Join(severityDisplay, " | "))
	}

	logger.Info("✨ Scan complete! Results saved to: " + opts.OutputDir)
	logger.Info("🎯 Run 'prismatic report --scan latest' to generate report")
}
