// Package core provides the core orchestration logic for finding enrichment.
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/joshsymonds/prismatic/internal/enrichment"
	"github.com/joshsymonds/prismatic/internal/enrichment/batch"
	"github.com/joshsymonds/prismatic/internal/enrichment/cache"
	"github.com/joshsymonds/prismatic/internal/enrichment/knowledge"
	"github.com/joshsymonds/prismatic/internal/enrichment/llm"
	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/joshsymonds/prismatic/internal/storage"
	"github.com/joshsymonds/prismatic/pkg/logger"
)

// Orchestrator implements the Enricher interface.
type Orchestrator struct {
	driver    llm.Driver
	strategy  batch.BatchingStrategy
	cache     cache.Cache
	knowledge knowledge.Base
	storage   *storage.Storage
	config    *enrichment.Config
	logger    logger.Logger
}

// NewOrchestrator creates a new enrichment orchestrator.
func NewOrchestrator(
	driver llm.Driver,
	strategy batch.BatchingStrategy,
	cache cache.Cache,
	knowledge knowledge.Base,
	storage *storage.Storage,
	config *enrichment.Config,
	logger logger.Logger,
) *Orchestrator {
	return &Orchestrator{
		driver:    driver,
		strategy:  strategy,
		cache:     cache,
		knowledge: knowledge,
		storage:   storage,
		config:    config,
		logger:    logger,
	}
}

// EnrichFindings implements the Enricher interface.
func (o *Orchestrator) EnrichFindings(ctx context.Context, findings []models.Finding, config *enrichment.Config) ([]enrichment.FindingEnrichment, error) {
	// Override config if provided
	if config != nil {
		o.config = config
	}

	// Create enrichment metadata
	metadata := &enrichment.Metadata{
		RunID:         uuid.New().String(),
		StartedAt:     time.Now(),
		TotalFindings: len(findings),
		Strategy:      o.strategy.Name(),
		Driver:        o.config.DriverName,
		LLMModel:      o.driver.GetCapabilities().ModelName,
	}

	o.logger.Info("Starting enrichment run",
		"run_id", metadata.RunID,
		"total_findings", metadata.TotalFindings,
		"strategy", metadata.Strategy,
		"driver", metadata.Driver,
	)

	// Create batches using the strategy
	batchConfig := &batch.Config{
		MaxTokensPerBatch:   o.config.TokenBudget / 10, // Rough estimate
		MaxFindingsPerBatch: 20,
		ClientContext:       o.config.ClientConfig,
	}

	batches, err := o.strategy.Batch(ctx, findings, batchConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create batches: %w", err)
	}

	o.logger.Info("Created batches", "batch_count", len(batches))

	// Process batches
	var enrichments []enrichment.FindingEnrichment
	var totalTokens int

	for i, batch := range batches {
		o.logger.Debug("Processing batch",
			"batch_number", i+1,
			"batch_id", batch.ID,
			"finding_count", len(batch.Findings),
		)

		// Check token budget
		if totalTokens >= o.config.TokenBudget {
			o.logger.Warn("Token budget exceeded, stopping enrichment",
				"used_tokens", totalTokens,
				"budget", o.config.TokenBudget,
			)
			break
		}

		// Check cache for each finding if enabled
		var uncachedFindings []models.Finding
		var cachedEnrichments []enrichment.FindingEnrichment

		if o.config.EnableCache && o.cache != nil {
			for _, finding := range batch.Findings {
				cached, err := o.cache.Get(ctx, finding.ID)
				if err == nil && cached != nil {
					cachedEnrichments = append(cachedEnrichments, *cached)
				} else {
					uncachedFindings = append(uncachedFindings, finding)
				}
			}

			if len(cachedEnrichments) > 0 {
				o.logger.Debug("Found cached enrichments",
					"cached_count", len(cachedEnrichments),
					"uncached_count", len(uncachedFindings),
				)
				enrichments = append(enrichments, cachedEnrichments...)
			}
		} else {
			uncachedFindings = batch.Findings
		}

		// Skip if all findings were cached
		if len(uncachedFindings) == 0 {
			continue
		}

		// Build prompt for the batch
		prompt, err := o.buildPrompt(ctx, uncachedFindings, &batch)
		if err != nil {
			o.logger.Error("Failed to build prompt", "error", err)
			metadata.Errors = append(metadata.Errors, fmt.Sprintf("batch %s: %v", batch.ID, err))
			continue
		}

		// Estimate tokens
		estimatedTokens, err := o.driver.EstimateTokens(prompt)
		if err != nil {
			o.logger.Warn("Failed to estimate tokens", "error", err)
			estimatedTokens = batch.EstimatedTokens
		}

		// Check if this batch would exceed budget
		if totalTokens+estimatedTokens > o.config.TokenBudget {
			o.logger.Warn("Batch would exceed token budget, skipping",
				"batch_id", batch.ID,
				"estimated_tokens", estimatedTokens,
			)
			break
		}

		// Call LLM driver
		batchEnrichments, err := o.driver.Enrich(ctx, uncachedFindings, prompt)
		if err != nil {
			o.logger.Error("Failed to enrich batch", "error", err, "batch_id", batch.ID)
			metadata.Errors = append(metadata.Errors, fmt.Sprintf("batch %s: %v", batch.ID, err))
			continue
		}

		// Update token count
		for _, e := range batchEnrichments {
			totalTokens += e.TokensUsed
		}

		// Cache enrichments if enabled
		if o.config.EnableCache && o.cache != nil {
			for _, e := range batchEnrichments {
				if err := o.cache.Set(ctx, &e, o.config.CacheTTL); err != nil {
					o.logger.Warn("Failed to cache enrichment",
						"finding_id", e.FindingID,
						"error", err,
					)
				}
			}
		}

		enrichments = append(enrichments, batchEnrichments...)
	}

	// Update metadata
	metadata.CompletedAt = time.Now()
	metadata.EnrichedFindings = len(enrichments)
	metadata.TotalTokensUsed = totalTokens

	// Save enrichments and metadata
	if err := o.saveEnrichments(ctx, enrichments, metadata); err != nil {
		return nil, fmt.Errorf("failed to save enrichments: %w", err)
	}

	o.logger.Info("Enrichment complete",
		"run_id", metadata.RunID,
		"enriched_findings", metadata.EnrichedFindings,
		"total_tokens", metadata.TotalTokensUsed,
		"duration", metadata.CompletedAt.Sub(metadata.StartedAt),
	)

	return enrichments, nil
}

// GetStrategy returns the batching strategy.
func (o *Orchestrator) GetStrategy() batch.BatchingStrategy {
	return o.strategy
}

// GetDriver returns the LLM driver.
func (o *Orchestrator) GetDriver() llm.Driver {
	return o.driver
}

// buildPrompt builds the prompt for a batch of findings.
func (o *Orchestrator) buildPrompt(ctx context.Context, findings []models.Finding, batch *batch.Batch) (string, error) {
	// Gather knowledge base entries if available
	var knowledgeEntries []*knowledge.Entry
	if o.knowledge != nil {
		for _, finding := range findings {
			// Search for relevant knowledge (e.g., by CVE ID, rule ID)
			if finding.Type != "" {
				entries, err := o.knowledge.Search(ctx, finding.Type, 3)
				if err == nil {
					knowledgeEntries = append(knowledgeEntries, entries...)
				}
			}
		}
	}

	// Build the prompt
	prompt := buildEnrichmentPrompt(findings, batch, knowledgeEntries, o.config.ClientConfig)
	return prompt, nil
}

// saveEnrichments saves enrichments to the storage.
func (o *Orchestrator) saveEnrichments(_ context.Context, enrichments []enrichment.FindingEnrichment, metadata *enrichment.Metadata) error {
	// Get the scan directory from storage
	scanDir := o.storage.GetScanDirectory()
	enrichmentDir := filepath.Join(scanDir, "enrichments")

	// Create enrichments directory
	if err := os.MkdirAll(enrichmentDir, 0750); err != nil {
		return fmt.Errorf("failed to create enrichments directory: %w", err)
	}

	// Save individual enrichments
	for _, enrichment := range enrichments {
		filename := filepath.Join(enrichmentDir, fmt.Sprintf("%s.json", enrichment.FindingID))
		data, err := json.MarshalIndent(enrichment, "", "  ")
		if err != nil {
			o.logger.Error("Failed to marshal enrichment",
				"finding_id", enrichment.FindingID,
				"error", err,
			)
			continue
		}

		if err := os.WriteFile(filename, data, 0600); err != nil {
			o.logger.Error("Failed to save enrichment",
				"finding_id", enrichment.FindingID,
				"error", err,
			)
			continue
		}
	}

	// Save metadata
	metadataFile := filepath.Join(enrichmentDir, "metadata.json")
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	if err := os.WriteFile(metadataFile, data, 0600); err != nil {
		return fmt.Errorf("failed to save metadata: %w", err)
	}

	return nil
}
