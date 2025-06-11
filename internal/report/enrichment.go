package report

import (
	"github.com/joshsymonds/prismatic/internal/config"
	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/joshsymonds/prismatic/pkg/logger"
)

// enrichFindings adds business context to findings based on configured metadata.
func enrichFindings(findings []models.Finding, cfg *config.Config, log logger.Logger) []models.Finding {
	// If no metadata enrichment is configured, return findings as-is
	if cfg == nil || len(cfg.MetadataEnrichment.Resources) == 0 {
		return findings
	}

	// Create a copy to avoid modifying the original
	enriched := make([]models.Finding, len(findings))
	copy(enriched, findings)

	enrichedCount := 0

	// Process each finding
	for i := range enriched {
		finding := &enriched[i]

		// Try to match resource metadata
		if resourceMetadata, ok := cfg.GetResourceMetadata(finding.Resource); ok {
			finding.BusinessContext = &models.BusinessContext{
				Owner:              resourceMetadata.Owner,
				DataClassification: resourceMetadata.DataClassification,
				BusinessImpact:     resourceMetadata.BusinessImpact,
				ComplianceImpact:   resourceMetadata.ComplianceImpact,
			}
			enrichedCount++

			log.Debug("Enriched finding with business context",
				"resource", finding.Resource,
				"owner", resourceMetadata.Owner,
			)
		}
	}

	log.Info("Completed finding enrichment",
		"enriched_count", enrichedCount,
		"resources_with_metadata", len(cfg.MetadataEnrichment.Resources),
	)

	return enriched
}
