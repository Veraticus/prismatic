// Package report implements the report command for generating security scan reports.
package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/joshsymonds/prismatic/internal/config"
	"github.com/joshsymonds/prismatic/internal/enrichment"
	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/joshsymonds/prismatic/internal/report"
	"github.com/joshsymonds/prismatic/internal/storage"
	"github.com/joshsymonds/prismatic/pkg/logger"
)

// Options represents report command options.
type Options struct {
	ScanPath          string
	OutputPath        string
	ModificationsFile string
	ConfigFile        string
	Formats           []string
}

// Run executes the report command.
func Run(args []string) error {
	opts := &Options{}

	// Parse command flags
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	fs.StringVar(&opts.ScanPath, "scan", "", "Path to scan results (or 'latest')")
	fs.StringVar(&opts.OutputPath, "output", "", "Output path for report")
	fs.StringVar(&opts.ModificationsFile, "modifications", "", "YAML file with manual modifications")
	fs.StringVar(&opts.ConfigFile, "config", "", "Configuration file for enrichment")

	// Handle --format flag
	var formatFlag string
	fs.StringVar(&formatFlag, "format", "html", "Report format(s): html,pdf,remediation,fix-bundle")

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `Usage: prismatic report [options]

Generate security report from scan results.

Options:`)
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, `
Examples:
  prismatic report --scan latest
  prismatic report --scan data/scans/2024-01-15-140000 --format pdf
  prismatic report --scan latest --modifications fixes.yaml --format html,pdf`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Validate required flags
	if opts.ScanPath == "" {
		return fmt.Errorf("--scan flag is required")
	}

	// Parse formats
	opts.Formats = strings.Split(formatFlag, ",")
	for i, f := range opts.Formats {
		opts.Formats[i] = strings.TrimSpace(f)
	}

	// Resolve scan path
	scanPath := opts.ScanPath
	if scanPath == "latest" {
		// Find the most recent scan directory
		scanPath = findLatestScan()
		if scanPath == "" {
			return fmt.Errorf("no scan results found")
		}
		logger.Info("Using latest scan", "path", scanPath)
	}

	// Generate output path if not specified
	if opts.OutputPath == "" {
		base := filepath.Base(scanPath)
		opts.OutputPath = filepath.Join("reports", fmt.Sprintf("%s-report", base))
	}

	logger.Info("Generating report",
		"scan", scanPath,
		"formats", opts.Formats,
		"output", opts.OutputPath,
	)

	// Load config if specified
	var cfg *config.Config
	if opts.ConfigFile != "" {
		var err error
		cfg, err = config.LoadConfig(opts.ConfigFile)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		logger.Info("Loaded config for enrichment", "file", opts.ConfigFile)
	}

	// Load scan data for new format system
	store := storage.NewStorageWithLogger("data", logger.GetGlobalLogger())

	// Load metadata
	metadata, err := store.LoadScanResults(scanPath)
	if err != nil {
		return fmt.Errorf("loading scan results: %w", err)
	}

	// Load findings
	findingsPath := filepath.Join(scanPath, "findings.json")
	var findings []models.Finding
	if err := loadJSONFile(findingsPath, &findings); err != nil {
		return fmt.Errorf("loading findings: %w", err)
	}

	// Load enrichments if available
	enrichments, _, err := store.LoadEnrichments(scanPath)
	if err != nil {
		logger.Warn("Failed to load AI enrichments", "error", err)
	}

	// Create enrichment map
	enrichmentMap := make(map[string]*enrichment.FindingEnrichment)
	for i := range enrichments {
		enrichmentMap[enrichments[i].FindingID] = &enrichments[i]
	}

	// Apply modifications if specified
	if opts.ModificationsFile != "" {
		mods, err := report.LoadModifications(opts.ModificationsFile)
		if err != nil {
			return fmt.Errorf("loading modifications: %w", err)
		}
		findings = mods.ApplyModificationsWithLogger(findings, logger.GetGlobalLogger())
		logger.Info("Applied modifications",
			"file", opts.ModificationsFile,
			"suppressions", len(mods.Suppressions),
			"overrides", len(mods.Overrides))
	}

	// Generate reports in requested formats
	for _, format := range opts.Formats {
		outputFile := opts.OutputPath
		if !strings.HasSuffix(outputFile, "."+format) {
			// remediation format outputs YAML
			if format == "remediation" && !strings.HasSuffix(outputFile, ".yaml") {
				outputFile = fmt.Sprintf("%s.yaml", opts.OutputPath)
			} else {
				outputFile = fmt.Sprintf("%s.%s", opts.OutputPath, format)
			}
		}

		// Handle legacy HTML/PDF formats specially for backward compatibility
		if format == "html" || format == "pdf" {
			// Create HTML generator
			generator, err := report.NewHTMLGenerator(scanPath, cfg)
			if err != nil {
				return fmt.Errorf("creating HTML generator: %w", err)
			}

			// Apply modifications if specified
			if opts.ModificationsFile != "" {
				if err := generator.ApplyModifications(opts.ModificationsFile); err != nil {
					return fmt.Errorf("applying modifications: %w", err)
				}
			}

			if format == "html" {
				if err := generator.Generate(outputFile); err != nil {
					return fmt.Errorf("generating HTML report: %w", err)
				}
			} else { // pdf
				// First generate HTML to a temporary file
				htmlFile := strings.TrimSuffix(outputFile, ".pdf") + ".html"
				if err := generator.Generate(htmlFile); err != nil {
					return fmt.Errorf("generating HTML for PDF: %w", err)
				}

				// Convert HTML to PDF
				if err := report.ConvertHTMLToPDF(htmlFile, outputFile); err != nil {
					return fmt.Errorf("converting HTML to PDF: %w", err)
				}
			}
		} else {
			// Use new format registry
			formatter, err := report.GetFormat(format, cfg, logger.GetGlobalLogger())
			if err != nil {
				return fmt.Errorf("getting format %s: %w", format, err)
			}

			if err := formatter.Generate(findings, enrichmentMap, metadata, outputFile); err != nil {
				return fmt.Errorf("generating %s report: %w", format, err)
			}
		}

		logger.Info("Generated report", "format", format, "file", outputFile)
	}

	return nil
}

func findLatestScan() string {
	// Find the most recent scan directory by sorting directory names
	scansDir := filepath.Join("data", "scans")

	entries, err := os.ReadDir(scansDir)
	if err != nil {
		return ""
	}

	var latest string
	for _, entry := range entries {
		if entry.IsDir() {
			if latest == "" || entry.Name() > latest {
				latest = entry.Name()
			}
		}
	}

	if latest != "" {
		return filepath.Join(scansDir, latest)
	}

	return ""
}

// loadJSONFile loads JSON data from a file.
func loadJSONFile(path string, v any) error {
	data, err := os.ReadFile(path) // #nosec G304 - path is validated by caller
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	buf.Write(data)

	decoder := json.NewDecoder(&buf)
	return decoder.Decode(v)
}
