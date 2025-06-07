package config

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Veraticus/prismatic/internal/config"
	"github.com/Veraticus/prismatic/pkg/logger"
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
	fmt.Printf("🔍 Validating configuration: %s\n\n", configFile)

	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		return fmt.Errorf("configuration is invalid: %w", err)
	}

	// Display validation results
	printValidationResults(cfg)

	fmt.Println("\n✅ Configuration is valid!")
	return nil
}

func printValidationResults(cfg *config.Config) {
	// Client information
	fmt.Println("📋 Client Information:")
	fmt.Printf("   Name: %s\n", cfg.Client.Name)
	fmt.Printf("   Environment: %s\n", cfg.Client.Environment)

	// AWS configuration
	if cfg.AWS != nil && (len(cfg.AWS.Profiles) > 0 || len(cfg.AWS.Regions) > 0) {
		fmt.Println("\n☁️  AWS Configuration:")
		if len(cfg.AWS.Profiles) > 0 {
			fmt.Printf("   Profiles: %s\n", strings.Join(cfg.AWS.Profiles, ", "))
		}
		if len(cfg.AWS.Regions) > 0 {
			fmt.Printf("   Regions: %s\n", strings.Join(cfg.AWS.Regions, ", "))
		}
	}

	// Docker configuration
	if cfg.Docker != nil && (len(cfg.Docker.Registries) > 0 || len(cfg.Docker.Containers) > 0) {
		fmt.Println("\n🐳 Docker Configuration:")
		if len(cfg.Docker.Registries) > 0 {
			fmt.Printf("   Registries: %s\n", strings.Join(cfg.Docker.Registries, ", "))
		}
		if len(cfg.Docker.Containers) > 0 {
			fmt.Printf("   Containers: %d configured\n", len(cfg.Docker.Containers))
			for _, container := range cfg.Docker.Containers {
				fmt.Printf("     - %s\n", container)
			}
		}
	}

	// Kubernetes configuration
	if cfg.Kubernetes != nil && (len(cfg.Kubernetes.Contexts) > 0 || len(cfg.Kubernetes.Namespaces) > 0) {
		fmt.Println("\n☸️  Kubernetes Configuration:")
		if len(cfg.Kubernetes.Contexts) > 0 {
			fmt.Printf("   Contexts: %s\n", strings.Join(cfg.Kubernetes.Contexts, ", "))
		}
		if len(cfg.Kubernetes.Namespaces) > 0 {
			fmt.Printf("   Namespaces: %s\n", strings.Join(cfg.Kubernetes.Namespaces, ", "))
		}
	}

	// Web endpoints
	if len(cfg.Endpoints) > 0 {
		fmt.Println("\n🌐 Web Endpoints:")
		for _, endpoint := range cfg.Endpoints {
			fmt.Printf("   - %s\n", endpoint)
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
		fmt.Printf("\n🔇 Suppressions: %d configured\n", suppressionCount)
		if cfg.Suppressions.Global.DateBefore != "" {
			fmt.Printf("   Global: Ignore findings before %s\n", cfg.Suppressions.Global.DateBefore)
		}
		for scanner, items := range cfg.Suppressions.Scanners {
			if len(items) > 0 {
				fmt.Printf("   %s: %d suppressions\n", scanner, len(items))
			}
		}
	}

	// Severity overrides
	if len(cfg.SeverityOverrides) > 0 {
		fmt.Printf("\n⚖️  Severity Overrides: %d configured\n", len(cfg.SeverityOverrides))
		for finding, severity := range cfg.SeverityOverrides {
			fmt.Printf("   %s → %s\n", finding, severity)
		}
	}

	// Metadata enrichment
	if len(cfg.MetadataEnrichment.Resources) > 0 {
		fmt.Printf("\n🏷️  Metadata Enrichment: %d resources configured\n", len(cfg.MetadataEnrichment.Resources))
	}

	// Scanners that will be used
	scanners := determineEnabledScanners(cfg)
	fmt.Printf("\n🔧 Enabled Scanners: %s\n", strings.Join(scanners, ", "))
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
