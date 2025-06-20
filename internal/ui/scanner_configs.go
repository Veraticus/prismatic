package ui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/joshsymonds/prismatic/internal/scanner"
	"github.com/joshsymonds/prismatic/internal/scanner/trivy"
)

// scannerConfigBuilder builds configuration fields for different scanner types.
type scannerConfigBuilder struct {
	config  scanner.Config
	scanner string
}

// newScannerConfigBuilder creates a new config builder for a scanner.
func newScannerConfigBuilder(scannerName string, factory scanner.Factory) *scannerConfigBuilder {
	return &scannerConfigBuilder{
		scanner: scannerName,
		config:  factory.DefaultConfig(),
	}
}

// buildFields creates configuration fields based on scanner type.
func (b *scannerConfigBuilder) buildFields() []ConfigField {
	switch b.scanner {
	case "Trivy":
		return b.buildTrivyFields()
	case "Nuclei":
		return b.buildNucleiFields()
	case "Gitleaks":
		return b.buildGitleaksFields()
	case "Prowler":
		return b.buildProwlerFields()
	case "Kubescape":
		return b.buildKubescapeFields()
	case "Checkov":
		return b.buildCheckovFields()
	default:
		// Return generic fields for unknown scanners
		return []ConfigField{
			{
				Key:         "enabled",
				Label:       "Enabled",
				Value:       "true",
				Type:        "bool",
				Description: "Enable this scanner",
				Required:    true,
			},
		}
	}
}

// buildTrivyFields builds fields for Trivy scanner configuration.
func (b *scannerConfigBuilder) buildTrivyFields() []ConfigField {
	// Cast to Trivy config
	cfg, ok := b.config.(*trivy.Config)
	if !ok {
		// Return default if cast fails
		cfg = trivy.DefaultConfig()
	}

	return []ConfigField{
		{
			Key:         "severities",
			Label:       "Severity Levels",
			Value:       strings.Join(cfg.Severities, ","),
			Type:        "text",
			Description: "Comma-separated list: CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN",
			Required:    true,
		},
		{
			Key:         "vuln_types",
			Label:       "Vulnerability Types",
			Value:       strings.Join(cfg.VulnTypes, ","),
			Type:        "text",
			Description: "Types to scan: vuln, secret, misconfig",
			Required:    true,
		},
		{
			Key:         "cache_dir",
			Label:       "Cache Directory",
			Value:       cfg.CacheDir,
			Type:        "text",
			Description: "Directory for vulnerability database cache",
		},
		{
			Key:         "ignore_unfixed",
			Label:       "Ignore Unfixed",
			Value:       strconv.FormatBool(cfg.IgnoreUnfixed),
			Type:        "bool",
			Description: "Skip vulnerabilities without fixes",
		},
		{
			Key:         "offline_mode",
			Label:       "Offline Mode",
			Value:       strconv.FormatBool(cfg.OfflineMode),
			Type:        "bool",
			Description: "Run without updating vulnerability database",
		},
		{
			Key:         "skip_db_update",
			Label:       "Skip DB Update",
			Value:       strconv.FormatBool(cfg.SkipDBUpdate),
			Type:        "bool",
			Description: "Skip vulnerability database update",
		},
		{
			Key:         "timeout",
			Label:       "Timeout (minutes)",
			Value:       strconv.Itoa(int(cfg.Timeout.Minutes())),
			Type:        "number",
			Description: "Scan timeout in minutes",
		},
		{
			Key:         "parallel",
			Label:       "Parallel Scans",
			Value:       strconv.Itoa(cfg.Parallel),
			Type:        "number",
			Description: "Number of parallel scans (0 = auto)",
		},
	}
}

// buildNucleiFields builds fields for Nuclei scanner configuration.
func (b *scannerConfigBuilder) buildNucleiFields() []ConfigField {
	return []ConfigField{
		{
			Key:         "templates",
			Label:       "Template Path",
			Value:       "",
			Type:        "text",
			Description: "Path to custom templates directory",
		},
		{
			Key:         "severity",
			Label:       "Severity Filter",
			Value:       "critical,high,medium",
			Type:        "text",
			Description: "Comma-separated severity levels",
			Required:    true,
		},
		{
			Key:         "rate_limit",
			Label:       "Rate Limit",
			Value:       "150",
			Type:        "number",
			Description: "Requests per second",
		},
		{
			Key:         "bulk_size",
			Label:       "Bulk Size",
			Value:       "25",
			Type:        "number",
			Description: "Number of hosts to scan in parallel",
		},
		{
			Key:         "timeout",
			Label:       "Timeout (seconds)",
			Value:       "5",
			Type:        "number",
			Description: "Request timeout in seconds",
		},
	}
}

// buildGitleaksFields builds fields for Gitleaks scanner configuration.
func (b *scannerConfigBuilder) buildGitleaksFields() []ConfigField {
	return []ConfigField{
		{
			Key:         "config_path",
			Label:       "Config Path",
			Value:       "",
			Type:        "text",
			Description: "Path to custom gitleaks config",
		},
		{
			Key:         "depth",
			Label:       "Scan Depth",
			Value:       "0",
			Type:        "number",
			Description: "Number of commits to scan (0 = all)",
		},
		{
			Key:         "redact",
			Label:       "Redact Secrets",
			Value:       "true",
			Type:        "bool",
			Description: "Redact secret values in output",
		},
		{
			Key:         "verbose",
			Label:       "Verbose Output",
			Value:       "false",
			Type:        "bool",
			Description: "Show detailed scan progress",
		},
	}
}

// buildProwlerFields builds fields for Prowler scanner configuration.
func (b *scannerConfigBuilder) buildProwlerFields() []ConfigField {
	return []ConfigField{
		{
			Key:         "regions",
			Label:       "AWS Regions",
			Value:       "us-east-1,us-west-2",
			Type:        "text",
			Description: "Comma-separated AWS regions",
			Required:    true,
		},
		{
			Key:         "compliance",
			Label:       "Compliance Frameworks",
			Value:       "",
			Type:        "text",
			Description: "e.g., cis_1.4_aws, pci_3.2.1_aws",
		},
		{
			Key:         "severity",
			Label:       "Severity Filter",
			Value:       "critical,high",
			Type:        "text",
			Description: "Minimum severity to report",
		},
		{
			Key:         "parallel",
			Label:       "Parallel Workers",
			Value:       "4",
			Type:        "number",
			Description: "Number of parallel checks",
		},
	}
}

// buildKubescapeFields builds fields for Kubescape scanner configuration.
func (b *scannerConfigBuilder) buildKubescapeFields() []ConfigField {
	return []ConfigField{
		{
			Key:         "frameworks",
			Label:       "Frameworks",
			Value:       "NSA,MITER",
			Type:        "text",
			Description: "Security frameworks to check",
			Required:    true,
		},
		{
			Key:         "namespaces",
			Label:       "Namespaces",
			Value:       "",
			Type:        "text",
			Description: "Specific namespaces (empty = all)",
		},
		{
			Key:         "severity_threshold",
			Label:       "Severity Threshold",
			Value:       "medium",
			Type:        "text",
			Description: "Minimum severity: low, medium, high",
		},
		{
			Key:         "verbose",
			Label:       "Verbose Output",
			Value:       "false",
			Type:        "bool",
			Description: "Show detailed results",
		},
	}
}

// buildCheckovFields builds fields for Checkov scanner configuration.
func (b *scannerConfigBuilder) buildCheckovFields() []ConfigField {
	return []ConfigField{
		{
			Key:         "frameworks",
			Label:       "Frameworks",
			Value:       "all",
			Type:        "text",
			Description: "e.g., terraform, kubernetes, dockerfile",
		},
		{
			Key:         "skip_checks",
			Label:       "Skip Checks",
			Value:       "",
			Type:        "text",
			Description: "Comma-separated check IDs to skip",
		},
		{
			Key:         "soft_fail",
			Label:       "Soft Fail",
			Value:       "false",
			Type:        "bool",
			Description: "Don't fail on findings",
		},
		{
			Key:         "compact",
			Label:       "Compact Output",
			Value:       "true",
			Type:        "bool",
			Description: "Minimal output format",
		},
	}
}

// applyFields applies field values back to the configuration.
func (b *scannerConfigBuilder) applyFields(fields []ConfigField, inputs []string) error {
	switch b.scanner {
	case "Trivy":
		return b.applyTrivyFields(fields, inputs)
	default:
		// No-op for unknown scanners
		return nil
	}
}

// applyTrivyFields applies field values to Trivy configuration.
func (b *scannerConfigBuilder) applyTrivyFields(fields []ConfigField, inputs []string) error {
	cfg, ok := b.config.(*trivy.Config)
	if !ok {
		return fmt.Errorf("invalid config type for Trivy")
	}

	for i, field := range fields {
		value := inputs[i]

		switch field.Key {
		case "severities":
			severities := strings.Split(value, ",")
			for j := range severities {
				severities[j] = strings.TrimSpace(severities[j])
			}
			cfg.Severities = severities

		case "vuln_types":
			types := strings.Split(value, ",")
			for j := range types {
				types[j] = strings.TrimSpace(types[j])
			}
			cfg.VulnTypes = types

		case "cache_dir":
			cfg.CacheDir = value

		case "ignore_unfixed":
			cfg.IgnoreUnfixed = value == "true"

		case "offline_mode":
			cfg.OfflineMode = value == "true"

		case "skip_db_update":
			cfg.SkipDBUpdate = value == "true"

		case "timeout":
			if minutes, err := strconv.Atoi(value); err == nil {
				cfg.Timeout = time.Duration(minutes) * time.Minute
			}

		case "parallel":
			if parallel, err := strconv.Atoi(value); err == nil {
				cfg.Parallel = parallel
			}
		}
	}

	return cfg.Validate()
}

// getConfig returns the configured scanner config.
func (b *scannerConfigBuilder) getConfig() scanner.Config {
	return b.config
}
