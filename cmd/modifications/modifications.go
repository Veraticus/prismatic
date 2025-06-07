package modifications

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Veraticus/prismatic/internal/report"
	"github.com/Veraticus/prismatic/pkg/logger"
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
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("creating output directory: %w", err)
		}
	}

	// Save to file
	if err := report.SaveModifications(outputPath, mods); err != nil {
		return fmt.Errorf("saving modifications: %w", err)
	}

	logger.Info("Generated example modifications file", "path", outputPath)
	fmt.Printf("✅ Example modifications file created: %s\n\n", outputPath)
	fmt.Println("Edit this file to:")
	fmt.Println("  - Suppress false positives")
	fmt.Println("  - Override severity levels")
	fmt.Println("  - Add comments to findings")
	fmt.Println("\nThen use with: prismatic report --scan latest --modifications", outputPath)

	return nil
}
