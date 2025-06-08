// Package config provides configuration loading and validation for Prismatic.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the complete configuration for a client scan.
type Config struct {
	Suppressions       SuppressionConfig  `yaml:"suppressions,omitempty"`
	AWS                *AWSConfig         `yaml:"aws,omitempty"`
	Docker             *DockerConfig      `yaml:"docker,omitempty"`
	Kubernetes         *KubernetesConfig  `yaml:"kubernetes,omitempty"`
	SeverityOverrides  map[string]string  `yaml:"severity_overrides,omitempty"`
	MetadataEnrichment MetadataEnrichment `yaml:"metadata_enrichment,omitempty"`
	Client             ClientConfig       `yaml:"client"`
	Endpoints          []string           `yaml:"endpoints,omitempty"`
}

// ClientConfig contains client identification information.
type ClientConfig struct {
	Name        string `yaml:"name"`
	Environment string `yaml:"environment"`
}

// AWSConfig contains AWS-specific scanning configuration.
type AWSConfig struct {
	Regions  []string `yaml:"regions"`
	Profiles []string `yaml:"profiles"`
}

// DockerConfig contains Docker/container scanning configuration.
type DockerConfig struct {
	Registries []string `yaml:"registries,omitempty"`
	Containers []string `yaml:"containers"`
}

// KubernetesConfig contains Kubernetes scanning configuration.
type KubernetesConfig struct {
	Contexts   []string `yaml:"contexts"`
	Namespaces []string `yaml:"namespaces,omitempty"` // Empty means all namespaces
}

// SuppressionConfig defines finding suppressions.
type SuppressionConfig struct {
	Scanners map[string][]string `yaml:",inline"`
	Global   GlobalSuppressions  `yaml:"global,omitempty"`
}

// GlobalSuppressions applies to all scanners.
type GlobalSuppressions struct {
	DateBefore string `yaml:"date_before,omitempty"` // Suppress findings before this date
}

// MetadataEnrichment adds business context to resources.
type MetadataEnrichment struct {
	Resources map[string]ResourceMetadata `yaml:"resources"`
}

// ResourceMetadata contains business context for a resource.
type ResourceMetadata struct {
	Owner              string   `yaml:"owner"`
	DataClassification string   `yaml:"data_classification"`
	BusinessImpact     string   `yaml:"business_impact,omitempty"`
	ComplianceImpact   []string `yaml:"compliance_impact,omitempty"`
}

// LoadConfig reads and parses a YAML configuration file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // Path is from trusted source (config file)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parsing config YAML: %w", err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
}

// Validate ensures the configuration is valid.
func (c *Config) Validate() error {
	if c.Client.Name == "" {
		return fmt.Errorf("client.name is required")
	}

	if c.Client.Environment == "" {
		return fmt.Errorf("client.environment is required")
	}

	// Validate at least one scanning target is configured
	hasTarget := c.AWS != nil && len(c.AWS.Profiles) > 0

	if c.Docker != nil && len(c.Docker.Containers) > 0 {
		hasTarget = true
	}
	if c.Kubernetes != nil && len(c.Kubernetes.Contexts) > 0 {
		hasTarget = true
	}
	if len(c.Endpoints) > 0 {
		hasTarget = true
	}

	if !hasTarget {
		return fmt.Errorf("at least one scanning target must be configured (AWS, Docker, Kubernetes, or Endpoints)")
	}

	// Validate date format if specified
	if c.Suppressions.Global.DateBefore != "" {
		if _, err := time.Parse("2006-01-02", c.Suppressions.Global.DateBefore); err != nil {
			return fmt.Errorf("invalid date format for suppressions.global.date_before: %w", err)
		}
	}

	return nil
}

// IsSuppressed checks if a finding should be suppressed based on configuration.
func (c *Config) IsSuppressed(scanner, findingType string, findingDate time.Time) (bool, string) {
	// Check global date suppression
	if c.Suppressions.Global.DateBefore != "" {
		cutoffDate, _ := time.Parse("2006-01-02", c.Suppressions.Global.DateBefore)
		if findingDate.Before(cutoffDate) {
			return true, fmt.Sprintf("Finding predates cutoff date %s", c.Suppressions.Global.DateBefore)
		}
	}

	// Check scanner-specific suppressions
	if suppressions, ok := c.Suppressions.Scanners[scanner]; ok {
		for _, suppression := range suppressions {
			if suppression == findingType {
				return true, fmt.Sprintf("Finding type %s is suppressed for %s scanner", findingType, scanner)
			}
		}
	}

	return false, ""
}

// GetSeverityOverride returns the overridden severity for a finding type, if any.
func (c *Config) GetSeverityOverride(findingType string) (string, bool) {
	if c.SeverityOverrides == nil {
		return "", false
	}
	severity, ok := c.SeverityOverrides[findingType]
	return severity, ok
}

// GetResourceMetadata returns metadata for a resource, if any.
func (c *Config) GetResourceMetadata(resource string) (ResourceMetadata, bool) {
	if c.MetadataEnrichment.Resources == nil {
		return ResourceMetadata{}, false
	}
	metadata, ok := c.MetadataEnrichment.Resources[resource]
	return metadata, ok
}
