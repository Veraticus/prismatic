// Package config implements the configuration validation command.
package config

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/joshsymonds/prismatic/internal/config"
	"github.com/joshsymonds/prismatic/pkg/logger"
)

// Run executes the config command.
func Run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("subcommand required: validate")
	}

	subcommand := args[0]
	subArgs := args[1:]

	switch subcommand {
	case "validate":
		return runValidate(subArgs)
	default:
		return fmt.Errorf("unknown subcommand: %s", subcommand)
	}
}

func runValidate(args []string) error {
	var configFile string

	fs := flag.NewFlagSet("config validate", flag.ExitOnError)
	fs.StringVar(&configFile, "config", "", "Configuration file to validate (required)")

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `Usage: prismatic config validate [options]

Validate a Prismatic configuration file.

Options:`)
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, `
Examples:
  prismatic config validate --config client-acme.yaml`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if configFile == "" {
		return fmt.Errorf("--config flag is required")
	}

	// Load and validate configuration
	logger.Info("Validating configuration", "file", configFile)

	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		return fmt.Errorf("configuration is invalid: %w", err)
	}

	// Display validation results
	printValidationResults(cfg)

	logger.Info("Configuration is valid!")
	return nil
}

func printValidationResults(cfg *config.Config) {
	// Client information
	logger.Info("Client Information",
		"name", cfg.Client.Name,
		"environment", cfg.Client.Environment)

	// AWS configuration
	if cfg.AWS != nil && (len(cfg.AWS.Profiles) > 0 || len(cfg.AWS.Regions) > 0) {
		logger.Info("AWS Configuration detected")
		if len(cfg.AWS.Profiles) > 0 {
			logger.Info("  Profiles", "profiles", strings.Join(cfg.AWS.Profiles, ", "))
		}
		if len(cfg.AWS.Regions) > 0 {
			logger.Info("  Regions", "regions", strings.Join(cfg.AWS.Regions, ", "))
		}
	}

	// Docker configuration
	if cfg.Docker != nil && (len(cfg.Docker.Registries) > 0 || len(cfg.Docker.Containers) > 0) {
		logger.Info("Docker Configuration detected")
		if len(cfg.Docker.Registries) > 0 {
			logger.Info("  Registries", "registries", strings.Join(cfg.Docker.Registries, ", "))
		}
		if len(cfg.Docker.Containers) > 0 {
			logger.Info("  Containers configured", "count", len(cfg.Docker.Containers))
			for _, container := range cfg.Docker.Containers {
				logger.Info("    Container", "name", container)
			}
		}
	}

	// Kubernetes configuration
	if cfg.Kubernetes != nil && (len(cfg.Kubernetes.Contexts) > 0 || len(cfg.Kubernetes.Namespaces) > 0) {
		logger.Info("Kubernetes Configuration detected")
		if len(cfg.Kubernetes.Contexts) > 0 {
			logger.Info("  Contexts", "contexts", strings.Join(cfg.Kubernetes.Contexts, ", "))
		}
		if len(cfg.Kubernetes.Namespaces) > 0 {
			logger.Info("  Namespaces", "namespaces", strings.Join(cfg.Kubernetes.Namespaces, ", "))
		}
	}

	// Web endpoints
	if len(cfg.Endpoints) > 0 {
		logger.Info("Web Endpoints detected", "count", len(cfg.Endpoints))
		for _, endpoint := range cfg.Endpoints {
			logger.Info("  Endpoint", "url", endpoint)
		}
	}

	// Suppressions
	suppressionCount := 0
	if cfg.Suppressions.Global.DateBefore != "" {
		suppressionCount++
	}
	for scanner, items := range cfg.Suppressions.Scanners {
		suppressionCount += len(items)
		logger.Debug("Scanner suppressions", "scanner", scanner, "count", len(items))
	}

	if suppressionCount > 0 {
		logger.Info("Suppressions configured", "total", suppressionCount)
		if cfg.Suppressions.Global.DateBefore != "" {
			logger.Info("  Global suppression", "ignore_before", cfg.Suppressions.Global.DateBefore)
		}
		for scanner, items := range cfg.Suppressions.Scanners {
			if len(items) > 0 {
				logger.Info("  Scanner suppressions", "scanner", scanner, "count", len(items))
			}
		}
	}

	// Severity overrides
	if len(cfg.SeverityOverrides) > 0 {
		logger.Info("Severity Overrides configured", "count", len(cfg.SeverityOverrides))
		for finding, severity := range cfg.SeverityOverrides {
			logger.Info("  Override", "finding", finding, "severity", severity)
		}
	}

	// Metadata enrichment
	if len(cfg.MetadataEnrichment.Resources) > 0 {
		logger.Info("Metadata Enrichment configured", "resources", len(cfg.MetadataEnrichment.Resources))
	}

	// Scanners that will be used
	scanners := determineEnabledScanners(cfg)
	logger.Info("Enabled Scanners", "scanners", strings.Join(scanners, ", "))
}

func determineEnabledScanners(cfg *config.Config) []string {
	scanners := []string{}

	// AWS Prowler
	if cfg.AWS != nil && (len(cfg.AWS.Profiles) > 0 || len(cfg.AWS.Regions) > 0) {
		scanners = append(scanners, "prowler")
	}

	// Docker Trivy
	if cfg.Docker != nil && len(cfg.Docker.Containers) > 0 {
		scanners = append(scanners, "trivy")
	}

	// Kubernetes Kubescape
	if cfg.Kubernetes != nil && len(cfg.Kubernetes.Contexts) > 0 {
		scanners = append(scanners, "kubescape")
	}

	// Web Nuclei
	if len(cfg.Endpoints) > 0 {
		scanners = append(scanners, "nuclei")
	}

	// Always enabled scanners (scan current directory)
	scanners = append(scanners, "gitleaks", "checkov")

	return scanners
}
