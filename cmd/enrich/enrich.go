package enrich

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/joshsymonds/prismatic/internal/config"
	"github.com/joshsymonds/prismatic/internal/enrichment"
	"github.com/joshsymonds/prismatic/internal/enrichment/batch"
	"github.com/joshsymonds/prismatic/internal/enrichment/cache"
	"github.com/joshsymonds/prismatic/internal/enrichment/core"
	"github.com/joshsymonds/prismatic/internal/enrichment/knowledge"
	"github.com/joshsymonds/prismatic/internal/enrichment/llm"
	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/joshsymonds/prismatic/internal/storage"
	"github.com/joshsymonds/prismatic/pkg/logger"
	"github.com/spf13/cobra"
)

var (
	configFile     string
	client         string
	scanDir        string
	strategy       string
	driver         string
	noCache        bool
	tokenBudget    int
	knowledgeBase  string
	maxConcurrency int
)

// NewEnrichCommand creates the enrich command.
func NewEnrichCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enrich",
		Short: "Enrich security findings with AI-powered analysis",
		Long: `Enrich security findings from a previous scan with contextual AI analysis.

This command reads findings from a scan directory and enriches them with:
- Business impact analysis
- Priority scoring
- Detailed remediation guidance
- Contextual insights based on your environment

The enrichment process is optional and can be skipped to save costs.`,
		Example: `  # Enrich findings from the latest scan
  prismatic enrich --client my-company

  # Enrich with a specific strategy
  prismatic enrich --client my-company --strategy critical-only

  # Enrich with a token budget
  prismatic enrich --client my-company --token-budget 50000

  # Use a specific scan directory
  prismatic enrich --scan-dir data/scans/my-company-2024-01-15`,
		RunE: runEnrich,
	}

	// Add flags
	cmd.Flags().StringVarP(&configFile, "config", "c", "", "Path to config file")
	cmd.Flags().StringVar(&client, "client", "", "Client name (required)")
	cmd.Flags().StringVar(&scanDir, "scan-dir", "", "Scan directory to enrich (defaults to latest)")
	cmd.Flags().StringVar(&strategy, "strategy", "smart-batch", "Batching strategy (smart-batch, critical-only, high-impact, all)")
	cmd.Flags().StringVar(&driver, "driver", "claude-cli", "LLM driver to use")
	cmd.Flags().BoolVar(&noCache, "no-cache", false, "Disable caching")
	cmd.Flags().IntVar(&tokenBudget, "token-budget", 100000, "Maximum tokens to use")
	cmd.Flags().StringVar(&knowledgeBase, "knowledge-base", "data/knowledge", "Path to knowledge base")
	cmd.Flags().IntVar(&maxConcurrency, "max-concurrency", 1, "Maximum concurrent LLM requests")

	cmd.MarkFlagRequired("client")

	return cmd
}

func runEnrich(cmd *cobra.Command, args []string) error {
	// Initialize logger
	log := logger.GetGlobalLogger()

	// Load config if provided
	var cfg *config.Config
	if configFile != "" {
		var err error
		cfg, err = config.LoadConfig(configFile)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
		log.Info("Loaded configuration", "config", configFile)
	} else {
		// Look for client-specific config
		clientConfigFile := fmt.Sprintf("configs/%s.yaml", client)
		if _, err := os.Stat(clientConfigFile); err == nil {
			var err error
			cfg, err = config.LoadConfig(clientConfigFile)
			if err != nil {
				return fmt.Errorf("failed to load client config: %w", err)
			}
			log.Info("Loaded client configuration", "config", clientConfigFile)
		}
	}

	// Determine scan directory
	if scanDir == "" {
		// Find latest scan for client
		dataDir := "data/scans"
		entries, err := os.ReadDir(dataDir)
		if err != nil {
			return fmt.Errorf("failed to read scan directory: %w", err)
		}

		var latestScan string
		var latestTime time.Time

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}

			// Check if it matches the client pattern
			if !containsClient(entry.Name(), client) {
				continue
			}

			info, err := entry.Info()
			if err != nil {
				continue
			}

			if info.ModTime().After(latestTime) {
				latestTime = info.ModTime()
				latestScan = entry.Name()
			}
		}

		if latestScan == "" {
			return fmt.Errorf("no scan found for client: %s", client)
		}

		scanDir = filepath.Join(dataDir, latestScan)
		log.Info("Using latest scan", "scan_dir", scanDir)
	}

	// Initialize storage
	store := storage.NewStorage(scanDir)

	// Load findings
	findings, err := loadFindings(store)
	if err != nil {
		return fmt.Errorf("failed to load findings: %w", err)
	}

	if len(findings) == 0 {
		log.Info("No findings to enrich")
		return nil
	}

	log.Info("Loaded findings", "count", len(findings))

	// Check if already enriched
	enrichmentDir := filepath.Join(scanDir, "enrichments")
	if _, err := os.Stat(filepath.Join(enrichmentDir, "metadata.json")); err == nil {
		log.Warn("Scan already enriched. To re-enrich, delete the enrichments directory first.")
		return fmt.Errorf("scan already enriched")
	}

	// Get LLM driver
	llmDriver, err := llm.DefaultRegistry.Get(driver)
	if err != nil {
		return fmt.Errorf("failed to get LLM driver: %w", err)
	}

	// Configure driver if config available
	if cfg != nil && cfg.Enrichment != nil && cfg.Enrichment.DriverConfig != nil {
		if err := llmDriver.Configure(cfg.Enrichment.DriverConfig); err != nil {
			return fmt.Errorf("failed to configure driver: %w", err)
		}
	}

	// Get batching strategy
	batchingStrategy, err := batch.DefaultRegistry.Get(strategy)
	if err != nil {
		return fmt.Errorf("failed to get batching strategy: %w", err)
	}

	// Initialize cache if enabled
	var enrichCache cache.Cache
	if !noCache {
		cacheDir := filepath.Join("data", "cache", "enrichments", client)
		enrichCache, err = cache.NewFileCache(cacheDir)
		if err != nil {
			return fmt.Errorf("failed to initialize cache: %w", err)
		}
		log.Info("Cache enabled", "cache_dir", cacheDir)
	}

	// Initialize knowledge base
	kb, err := knowledge.NewFileBase(knowledgeBase)
	if err != nil {
		return fmt.Errorf("failed to initialize knowledge base: %w", err)
	}
	log.Info("Knowledge base initialized", "path", knowledgeBase)

	// Build enrichment config
	enrichConfig := &enrichment.Config{
		Strategy:          strategy,
		DriverName:        driver,
		TokenBudget:       tokenBudget,
		CacheTTL:          24 * time.Hour, // Default 24h cache
		KnowledgeBasePath: knowledgeBase,
		EnableCache:       !noCache,
	}

	// Add client config if available
	if cfg != nil {
		enrichConfig.ClientConfig = map[string]interface{}{
			"client_name": cfg.Client.Name,
			"environment": cfg.Client.Environment,
		}

		// Add AWS profiles and regions if available
		if cfg.AWS != nil {
			enrichConfig.ClientConfig["aws_profiles"] = cfg.AWS.Profiles
			enrichConfig.ClientConfig["aws_regions"] = cfg.AWS.Regions
		}

		// Add production indicators
		if cfg.Enrichment != nil {
			if cfg.Enrichment.ProductionAccounts != nil {
				enrichConfig.ClientConfig["production_accounts"] = cfg.Enrichment.ProductionAccounts
			}
			if cfg.Enrichment.ProductionNamespaces != nil {
				enrichConfig.ClientConfig["production_namespaces"] = cfg.Enrichment.ProductionNamespaces
			}
		}
	}

	// Override config values from flags
	if tokenBudget > 0 {
		enrichConfig.TokenBudget = tokenBudget
	}

	// Create orchestrator
	orchestrator := core.NewOrchestrator(
		llmDriver,
		batchingStrategy,
		enrichCache,
		kb,
		store,
		enrichConfig,
		log,
	)

	// Run enrichment
	log.Info("Starting enrichment",
		"strategy", strategy,
		"driver", driver,
		"token_budget", enrichConfig.TokenBudget,
	)

	ctx := context.Background()
	enrichments, err := orchestrator.EnrichFindings(ctx, findings, enrichConfig)
	if err != nil {
		return fmt.Errorf("enrichment failed: %w", err)
	}

	log.Info("Enrichment complete",
		"enriched_findings", len(enrichments),
		"scan_dir", scanDir,
	)

	// Print summary
	fmt.Println("\n✨ Enrichment Summary:")
	fmt.Printf("  Total findings: %d\n", len(findings))
	fmt.Printf("  Enriched findings: %d\n", len(enrichments))
	fmt.Printf("  Strategy: %s\n", strategy)
	fmt.Printf("  Driver: %s\n", driver)
	fmt.Printf("\nEnrichments saved to: %s\n", filepath.Join(scanDir, "enrichments"))
	fmt.Println("\nRun 'prismatic report' to generate an enriched report.")

	return nil
}

// loadFindings loads all findings from storage.
func loadFindings(store *storage.Storage) ([]models.Finding, error) {
	var allFindings []models.Finding

	// Get all scanner results
	scanners := []string{"prowler", "trivy", "kubescape", "nuclei", "gitleaks", "checkov"}

	for _, scanner := range scanners {
		results, err := store.LoadResults(scanner)
		if err != nil {
			continue // Scanner might not have been run
		}

		allFindings = append(allFindings, results.Findings...)
	}

	return allFindings, nil
}

// containsClient checks if a directory name contains the client name.
func containsClient(dirName, client string) bool {
	return len(dirName) >= len(client) && dirName[:len(client)] == client
}

// Run executes the enrich command with the provided arguments.
func Run(args []string) error {
	cmd := NewEnrichCommand()
	cmd.SetArgs(args)
	return cmd.Execute()
}
