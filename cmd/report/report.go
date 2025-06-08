// Package report implements the report command for generating security scan reports.
package report

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Veraticus/prismatic/internal/report"
	"github.com/Veraticus/prismatic/pkg/logger"
)

// Options represents report command options.
type Options struct {
	ScanPath          string
	OutputPath        string
	ModificationsFile string
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

	// Handle --format flag
	var formatFlag string
	fs.StringVar(&formatFlag, "format", "html", "Report format(s): html,pdf")

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
		if f != "html" && f != "pdf" {
			return fmt.Errorf("unsupported format: %s", f)
		}
	}

	// Resolve scan path
	scanPath := opts.ScanPath
	if scanPath == "latest" {
		// TODO: Find the most recent scan directory
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

	// Create HTML generator
	generator, err := report.NewHTMLGenerator(scanPath)
	if err != nil {
		return fmt.Errorf("creating report generator: %w", err)
	}

	// Apply modifications if specified
	if opts.ModificationsFile != "" {
		if err := generator.ApplyModifications(opts.ModificationsFile); err != nil {
			return fmt.Errorf("applying modifications: %w", err)
		}
	}

	// Generate reports in requested formats
	for _, format := range opts.Formats {
		outputFile := opts.OutputPath
		if !strings.HasSuffix(outputFile, "."+format) {
			outputFile = fmt.Sprintf("%s.%s", opts.OutputPath, format)
		}

		switch format {
		case "html":
			if err := generator.Generate(outputFile); err != nil {
				return fmt.Errorf("generating HTML report: %w", err)
			}
		case "pdf":
			// First generate HTML to a temporary file
			htmlFile := strings.TrimSuffix(outputFile, ".pdf") + ".html"
			if err := generator.Generate(htmlFile); err != nil {
				return fmt.Errorf("generating HTML for PDF: %w", err)
			}

			// Convert HTML to PDF
			if err := report.ConvertHTMLToPDF(htmlFile, outputFile); err != nil {
				return fmt.Errorf("converting HTML to PDF: %w", err)
			}

			// Optionally remove the intermediate HTML file
			// os.Remove(htmlFile)
		}

		logger.Info("Generated report", "format", format, "file", outputFile)
	}

	return nil
}

func findLatestScan() string {
	// TODO: Implement finding the most recent scan
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
