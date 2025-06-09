// Package config provides configuration loading and validation for Prismatic.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Veraticus/prismatic/pkg/pathutil"
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
	Repositories       []Repository       `yaml:"repositories,omitempty"`
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
	Kubeconfig string   `yaml:"kubeconfig,omitempty"` // Path to kubeconfig file
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

// Repository represents a Git repository to scan.
type Repository struct {
	Name   string `yaml:"name"`
	Path   string `yaml:"path"` // Can be URL or local path
	Branch string `yaml:"branch"`
}

// LoadConfig reads and parses a YAML configuration file.
func LoadConfig(path string) (*Config, error) {
	// Validate the config file path
	validPath, err := pathutil.ValidateConfigPath(path)
	if err != nil {
		return nil, fmt.Errorf("invalid config path: %w", err)
	}

	data, err := os.ReadFile(validPath) // #nosec G304 - path is validated
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
	if len(c.Repositories) > 0 {
		hasTarget = true
	}

	if !hasTarget {
		return fmt.Errorf("at least one scanning target must be configured (AWS, Docker, Kubernetes, Endpoints, or Repositories)")
	}

	// Validate date format if specified
	if c.Suppressions.Global.DateBefore != "" {
		if _, err := time.Parse("2006-01-02", c.Suppressions.Global.DateBefore); err != nil {
			return fmt.Errorf("invalid date format for suppressions.global.date_before: %w", err)
		}
	}

	// Validate kubeconfig file exists if specified
	if c.Kubernetes != nil && c.Kubernetes.Kubeconfig != "" {
		// Expand tilde to home directory
		kubeconfigPath := c.Kubernetes.Kubeconfig
		if strings.HasPrefix(kubeconfigPath, "~/") {
			homeDir, err := os.UserHomeDir()
			if err == nil {
				kubeconfigPath = filepath.Join(homeDir, kubeconfigPath[2:])
			}
		}

		if _, err := os.Stat(kubeconfigPath); err != nil {
			return fmt.Errorf("kubeconfig file not found: %s", c.Kubernetes.Kubeconfig)
		}
	}

	// Validate AWS regions if configured
	if c.AWS != nil && len(c.AWS.Regions) > 0 {
		validRegions := getValidAWSRegions()
		for _, region := range c.AWS.Regions {
			if !isValidAWSRegion(region, validRegions) {
				return fmt.Errorf("invalid AWS region: %s", region)
			}
		}
	}

	return nil
}

// isValidAWSRegion checks if a region is valid.
func isValidAWSRegion(region string, validRegions map[string]bool) bool {
	return validRegions[region]
}

// getValidAWSRegions returns a map of valid AWS regions.
func getValidAWSRegions() map[string]bool {
	return map[string]bool{
		// US Regions
		"us-east-1": true, // N. Virginia
		"us-east-2": true, // Ohio
		"us-west-1": true, // N. California
		"us-west-2": true, // Oregon
		// EU Regions
		"eu-west-1":    true, // Ireland
		"eu-west-2":    true, // London
		"eu-west-3":    true, // Paris
		"eu-central-1": true, // Frankfurt
		"eu-central-2": true, // Zurich
		"eu-north-1":   true, // Stockholm
		"eu-south-1":   true, // Milan
		"eu-south-2":   true, // Spain
		// Asia Pacific Regions
		"ap-southeast-1": true, // Singapore
		"ap-southeast-2": true, // Sydney
		"ap-southeast-3": true, // Jakarta
		"ap-southeast-4": true, // Melbourne
		"ap-northeast-1": true, // Tokyo
		"ap-northeast-2": true, // Seoul
		"ap-northeast-3": true, // Osaka
		"ap-south-1":     true, // Mumbai
		"ap-south-2":     true, // Hyderabad
		"ap-east-1":      true, // Hong Kong
		// Other Regions
		"ca-central-1": true, // Canada
		"ca-west-1":    true, // Calgary
		"sa-east-1":    true, // São Paulo
		"me-south-1":   true, // Bahrain
		"me-central-1": true, // UAE
		"af-south-1":   true, // Cape Town
		"il-central-1": true, // Tel Aviv
		// GovCloud
		"us-gov-east-1": true, // GovCloud East
		"us-gov-west-1": true, // GovCloud West
	}
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
