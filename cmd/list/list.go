// Package list implements the list command for viewing previous scans.
package list

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/joshsymonds/prismatic/internal/storage"
	"github.com/joshsymonds/prismatic/pkg/logger"
)

// Options represents list command options.
type Options struct {
	Client  string
	DataDir string
	Format  string
	Limit   int
}

// Run executes the list command.
func Run(args []string) error {
	opts := &Options{}

	// Parse command flags
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	fs.StringVar(&opts.Client, "client", "", "Filter by client name")
	fs.IntVar(&opts.Limit, "limit", 10, "Maximum number of scans to show")
	fs.StringVar(&opts.DataDir, "data-dir", "data", "Data directory path")
	fs.StringVar(&opts.Format, "format", "table", "Output format (table, json)")

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `Usage: prismatic list [options]

List previous security scans.

Options:`)
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, `
Examples:
  prismatic list
  prismatic list --client acme
  prismatic list --limit 20
  prismatic list --format json`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Create storage instance
	store := storage.NewStorage(opts.DataDir)

	// List scans
	scans, err := store.ListScans(opts.Client, opts.Limit)
	if err != nil {
		return fmt.Errorf("listing scans: %w", err)
	}

	if len(scans) == 0 {
		if opts.Client != "" {
			logger.Info("No scans found for client", "client", opts.Client)
		} else {
			logger.Info("No scans found")
		}
		return nil
	}

	// Display results based on format
	switch opts.Format {
	case "json":
		return displayJSON(scans)
	default:
		return displayTable(scans)
	}
}

func displayTable(scans []storage.ScanInfo) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	// Print header
	if _, err := fmt.Fprintln(w, "ID\tCLIENT\tENVIRONMENT\tFINDINGS\tDURATION\tTIME AGO"); err != nil {
		return fmt.Errorf("writing header: %w", err)
	}
	if _, err := fmt.Fprintln(w, strings.Repeat("-", 80)); err != nil {
		return fmt.Errorf("writing separator: %w", err)
	}

	for _, scan := range scans {
		// Calculate time ago
		timeAgo := formatTimeAgo(scan.StartTime)

		// Calculate duration
		duration := scan.EndTime.Sub(scan.StartTime).Round(time.Second)

		// Format findings count with severity breakdown
		findings := fmt.Sprintf("%d", scan.Summary.TotalFindings)
		criticalHigh := scan.Summary.BySeverity["critical"] + scan.Summary.BySeverity["high"]
		if criticalHigh > 0 {
			findings = fmt.Sprintf("%d (🚨 %d)", scan.Summary.TotalFindings, criticalHigh)
		}

		// Add warning if any scanners failed
		if len(scan.Summary.FailedScanners) > 0 {
			findings += " ⚠️"
		}

		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			scan.ID,
			scan.ClientName,
			scan.Environment,
			findings,
			duration,
			timeAgo,
		); err != nil {
			return fmt.Errorf("writing scan entry: %w", err)
		}
	}

	if err := w.Flush(); err != nil {
		return fmt.Errorf("flushing table writer: %w", err)
	}

	// Print footer with usage hint
	logger.Info("💡 Use 'prismatic report --scan' to generate a report", "scan", scans[0].ID)

	return nil
}

func displayJSON(scans []storage.ScanInfo) error {
	// For JSON output, we'll implement this when we implement the report command
	// For now, just show a simple implementation
	for _, scan := range scans {
		//nolint:forbidigo // JSON output format
		fmt.Printf(`{
  "id": "%s",
  "client": "%s",
  "environment": "%s",
  "start_time": "%s",
  "end_time": "%s",
  "total_findings": %d,
  "path": "%s"
}
`, scan.ID, scan.ClientName, scan.Environment,
			scan.StartTime.Format(time.RFC3339),
			scan.EndTime.Format(time.RFC3339),
			scan.Summary.TotalFindings,
			scan.Path)
	}
	return nil
}

func formatTimeAgo(t time.Time) string {
	duration := time.Since(t)

	switch {
	case duration < time.Minute:
		return "just now"
	case duration < time.Hour:
		minutes := int(duration.Minutes())
		if minutes == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", minutes)
	case duration < 24*time.Hour:
		hours := int(duration.Hours())
		if hours == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", hours)
	case duration < 7*24*time.Hour:
		days := int(duration.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	case duration < 30*24*time.Hour:
		weeks := int(duration.Hours() / 24 / 7)
		if weeks == 1 {
			return "1 week ago"
		}
		return fmt.Sprintf("%d weeks ago", weeks)
	default:
		return t.Format("Jan 2, 2006")
	}
}
