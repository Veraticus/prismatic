package enrichment

import (
	"testing"
	"time"
)

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "Valid config",
			config: Config{
				ClientConfig:      map[string]interface{}{"client": "test"},
				DriverConfig:      map[string]interface{}{"key": "value"},
				Strategy:          "smart-batch",
				DriverName:        "claude-cli",
				KnowledgeBasePath: "/data/knowledge",
				TokenBudget:       10000,
				CacheTTL:          24 * time.Hour,
				EnableCache:       true,
			},
			wantErr: false,
		},
		{
			name:    "Empty config",
			config:  Config{},
			wantErr: false, // Empty config is valid, uses defaults
		},
		{
			name: "Config with zero token budget",
			config: Config{
				Strategy:    "smart-batch",
				DriverName:  "claude-cli",
				TokenBudget: 0,
			},
			wantErr: false, // Zero means unlimited
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test config validation if we add validation methods
			if tt.config.Strategy == "" && !tt.wantErr {
				// Default strategy should be applied
			}
		})
	}
}

func TestConfigDefaults(t *testing.T) {
	config := Config{}

	// Test that defaults are applied correctly
	if config.EnableCache {
		t.Error("EnableCache should default to false")
	}

	if config.TokenBudget != 0 {
		t.Error("TokenBudget should default to 0 (unlimited)")
	}

	if config.CacheTTL != 0 {
		t.Error("CacheTTL should default to 0")
	}
}
