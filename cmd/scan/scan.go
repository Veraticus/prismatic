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
	fs.IntVar(&opts.Timeout, "timeout", 300, "Timeout in seconds per scanner")
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

	logger.Info("Starting security scan",
		"client", cfg.Client.Name,
		"environment", cfg.Client.Environment,
		"output", opts.OutputDir,
	)

	// Create scan context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(opts.Timeout)*time.Second)
	defer cancel()

	// Initialize orchestrator
	orchestrator := scanner.NewOrchestrator(cfg, opts.OutputDir, opts.Mock)

	// Prepare repositories if configured
	if len(cfg.Repositories) > 0 {
		printScanProgress("Cloning repositories...")
		if prepErr := orchestrator.PrepareRepositories(ctx); prepErr != nil {
			return fmt.Errorf("preparing repositories: %w", prepErr)
		}
		defer orchestrator.CleanupRepositories()
	}

	// Initialize scanners
	if initErr := orchestrator.InitializeScanners(opts.OnlyScanners); initErr != nil {
		return fmt.Errorf("initializing scanners: %w", initErr)
	}

	// Run scans
	printScanProgress("Starting scans...")
	metadata, err := orchestrator.RunScans(ctx)
	if err != nil {
		return fmt.Errorf("running scans: %w", err)
	}

	// Set additional metadata
	metadata.ID = filepath.Base(opts.OutputDir)
	metadata.ConfigFile = opts.ConfigFile

	// Save results
	store := storage.NewStorage("data")
	if err := store.SaveScanResults(opts.OutputDir, metadata); err != nil {
		return fmt.Errorf("saving results: %w", err)
	}

	// Print scan summary
	printScanSummary(metadata, opts)

	return nil
}

func printScanProgress(msg string) {
	logger.Info("➜ " + msg)
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
