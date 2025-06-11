// Package modifications provides the CLI command for generating example modifications files.
// These files allow users to suppress false positives, override severity levels, and add
// comments to security findings before generating reports.
package modifications

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joshsymonds/prismatic/internal/report"
	"github.com/joshsymonds/prismatic/pkg/logger"
)

// Run executes the modifications command.
func Run(args []string) error {
	var outputPath string

	// Parse command flags
	fs := flag.NewFlagSet("modifications", flag.ExitOnError)
	fs.StringVar(&outputPath, "output", "fixes.yaml", "Output path for example modifications file")

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `Usage: prismatic modifications [options]

Generate an example modifications file for manual finding adjustments.

Options:`)
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, `
Examples:
  prismatic modifications
  prismatic modifications --output custom-fixes.yaml`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Create example modifications
	mods := report.Example()

	// Ensure output directory exists
	if dir := filepath.Dir(outputPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("creating output directory: %w", err)
		}
	}

	// Save to file
	if err := report.SaveModifications(outputPath, mods); err != nil {
		return fmt.Errorf("saving modifications: %w", err)
	}

	logger.Info("Generated example modifications file", "path", outputPath)
	logger.Info("✅ Example modifications file created", "path", outputPath)
	logger.Info("Edit this file to:")
	logger.Info("  - Suppress false positives")
	logger.Info("  - Override severity levels")
	logger.Info("  - Add comments to findings")
	logger.Info("Then use with: prismatic report --scan latest --modifications", "path", outputPath)

	return nil
}
