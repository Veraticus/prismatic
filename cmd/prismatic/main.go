// Package main is the entry point for the Prismatic security scanner CLI.
// Prismatic orchestrates multiple open-source security tools to perform comprehensive
// security assessments across AWS, Kubernetes, containers, infrastructure-as-code,
// and web applications, then generates unified reports from the scan results.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/joshsymonds/prismatic/cmd/config"
	"github.com/joshsymonds/prismatic/cmd/enrich"
	"github.com/joshsymonds/prismatic/cmd/list"
	"github.com/joshsymonds/prismatic/cmd/modifications"
	"github.com/joshsymonds/prismatic/cmd/report"
	"github.com/joshsymonds/prismatic/cmd/scan"
	"github.com/joshsymonds/prismatic/pkg/logger"
)

var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Global flags
	var (
		debug       bool
		logFormat   string
		showVersion bool
	)

	// Create a new flag set for global flags
	globalFlags := flag.NewFlagSet("prismatic", flag.ExitOnError)
	globalFlags.BoolVar(&debug, "debug", false, "Enable debug logging")
	globalFlags.StringVar(&logFormat, "log-format", "text", "Log format (text or json)")
	globalFlags.BoolVar(&showVersion, "version", false, "Show version information")

	// Parse global flags first
	if err := globalFlags.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	if showVersion {
		fmt.Printf("prismatic version %s (built %s)\n", version, buildTime) //nolint:forbidigo
		os.Exit(0)
	}

	// Setup logger
	logger.SetupLogger(debug, logFormat)

	// Get the command
	args := globalFlags.Args()
	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	command := args[0]
	commandArgs := args[1:]

	// Route to appropriate command
	switch command {
	case "scan":
		if err := runScan(commandArgs); err != nil {
			logger.Error("scan failed", "error", err)
			os.Exit(1)
		}
	case "report":
		if err := runReport(commandArgs); err != nil {
			logger.Error("report generation failed", "error", err)
			os.Exit(1)
		}
	case "enrich":
		if err := runEnrich(commandArgs); err != nil {
			logger.Error("enrichment failed", "error", err)
			os.Exit(1)
		}
	case "list":
		if err := runList(commandArgs); err != nil {
			logger.Error("list failed", "error", err)
			os.Exit(1)
		}
	case "config":
		if err := runConfig(commandArgs); err != nil {
			logger.Error("config validation failed", "error", err)
			os.Exit(1)
		}
	case "modifications":
		if err := runModifications(commandArgs); err != nil {
			logger.Error("modifications generation failed", "error", err)
			os.Exit(1)
		}
	case "help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	//nolint:forbidigo
	fmt.Println(`🔍 Prismatic Security Scanner

Usage:
  prismatic [global flags] <command> [command flags]

Commands:
  scan           Run security scans
  enrich         Enrich findings with AI-powered analysis
  report         Generate report from scan data
  list           List previous scans
  config         Validate configuration
  modifications  Generate example modifications file
  help           Show this help message

Global Flags:
  --debug         Enable debug logging
  --log-format    Log format (text or json) (default: text)
  --version       Show version information

Examples:
  prismatic scan --config client-acme.yaml
  prismatic report --scan latest --format html
  prismatic list --client acme --limit 10
  prismatic config validate --config client-acme.yaml

Use "prismatic <command> --help" for more information about a command.`)
}

func runScan(args []string) error {
	return scan.Run(args)
}

func runReport(args []string) error {
	return report.Run(args)
}

func runEnrich(args []string) error {
	return enrich.Run(args)
}

func runList(args []string) error {
	return list.Run(args)
}

func runConfig(args []string) error {
	return config.Run(args)
}

func runModifications(args []string) error {
	return modifications.Run(args)
}
