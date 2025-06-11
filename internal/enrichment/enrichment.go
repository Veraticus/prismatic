package enrichment

import (
	"time"
)

// Enricher is the main interface for enriching security findings.

// Config contains configuration for the enrichment process.
type Config struct {
	ClientConfig      map[string]interface{} `yaml:"client_config"`
	DriverConfig      map[string]interface{} `yaml:"driver_config"`
	Strategy          string                 `yaml:"strategy"`
	DriverName        string                 `yaml:"driver"`
	KnowledgeBasePath string                 `yaml:"knowledge_base_path"`
	TokenBudget       int                    `yaml:"token_budget"`
	CacheTTL          time.Duration          `yaml:"cache_ttl"`
	EnableCache       bool                   `yaml:"enable_cache"`
}
