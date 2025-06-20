// Package remediation provides types and functionality for generating remediation manifests and fix bundles.
package remediation

import (
	"strings"
	"time"

	"github.com/joshsymonds/prismatic/internal/enrichment"
	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/joshsymonds/prismatic/pkg/logger"
)

// FindingGrouper groups findings by remediation strategy.
type FindingGrouper struct {
	logger logger.Logger
}

// NewFindingGrouper creates a new finding grouper.
func NewFindingGrouper(_ any, log logger.Logger) *FindingGrouper {
	return &FindingGrouper{
		logger: log,
	}
}

// GroupByRemediation groups findings that can be fixed together.
func (g *FindingGrouper) GroupByRemediation(findings []models.Finding, enrichments map[string]*enrichment.FindingEnrichment) []Group {
	// Create a map to collect findings by strategy
	strategyMap := make(map[string][]models.Finding)

	for _, finding := range findings {
		strategy := g.determineStrategy(finding, enrichments[finding.ID])
		strategyMap[strategy] = append(strategyMap[strategy], finding)
	}

	// Convert map to groups
	groups := make([]Group, 0, len(strategyMap))
	for strategy, findings := range strategyMap {
		group := Group{
			Findings:        findings,
			Strategy:        strategy,
			RepositoryType:  g.getRepositoryType(strategy),
			Priority:        g.calculatePriority(findings),
			EstimatedEffort: g.estimateEffort(strategy, len(findings)),
		}
		groups = append(groups, group)
	}

	return groups
}

// determineStrategy identifies the remediation strategy for a finding.
func (g *FindingGrouper) determineStrategy(finding models.Finding, _ *enrichment.FindingEnrichment) string {
	// Use scanner and finding type to determine strategy
	scanner := finding.Scanner
	findingType := strings.ToLower(finding.Type)

	switch scanner {
	case "prowler", "mock-prowler":
		return g.determineProwlerStrategy(finding)
	case "trivy", "mock-trivy":
		return g.determineTrivyStrategy(finding)
	case "kubescape", "mock-kubescape":
		return g.determineKubescapeStrategy(finding)
	case "checkov", "mock-checkov":
		return g.determineCheckovStrategy(finding)
	case "nuclei", "mock-nuclei":
		return "web-configuration"
	case "gitleaks", "mock-gitleaks":
		return "secrets-rotation"
	default:
		// Fallback to generic strategy
		if strings.Contains(findingType, "terraform") {
			return "terraform-generic"
		} else if strings.Contains(findingType, "kubernetes") || strings.Contains(findingType, "k8s") {
			return "kubernetes-generic"
		}
		return "generic"
	}
}

// determineProwlerStrategy categorizes Prowler findings.
func (g *FindingGrouper) determineProwlerStrategy(finding models.Finding) string {
	findingType := strings.ToLower(finding.Type)
	resource := strings.ToLower(finding.Resource)

	// S3 related findings
	if strings.Contains(resource, "s3") || strings.Contains(findingType, "s3") {
		switch {
		case strings.Contains(findingType, "public") || strings.Contains(findingType, "access"):
			return "terraform-s3-public-access"
		case strings.Contains(findingType, "encryption"):
			return "terraform-s3-encryption"
		case strings.Contains(findingType, "versioning"):
			return "terraform-s3-versioning"
		}
	}

	// RDS related findings
	if strings.Contains(resource, "rds") || strings.Contains(resource, "db") || strings.Contains(findingType, "rds") {
		if strings.Contains(findingType, "encrypt") { // Changed to match both "encrypted" and "encryption"
			return "terraform-rds-encryption"
		} else if strings.Contains(findingType, "backup") {
			return "terraform-rds-backup"
		}
	}

	// IAM related findings
	if strings.Contains(resource, "iam") || strings.Contains(findingType, "iam") {
		if strings.Contains(findingType, "mfa") {
			return "aws-iam-mfa"
		} else if strings.Contains(findingType, "policy") || strings.Contains(findingType, "permission") {
			return "terraform-iam-policy"
		}
	}

	// EC2 related findings
	if strings.Contains(resource, "ec2") || strings.Contains(resource, "instance") {
		if strings.Contains(findingType, "public") || strings.Contains(findingType, "security") {
			return "terraform-ec2-security-group"
		}
	}

	return "aws-generic"
}

// determineTrivyStrategy categorizes Trivy findings.
func (g *FindingGrouper) determineTrivyStrategy(finding models.Finding) string {
	findingType := strings.ToLower(finding.Type)

	if strings.Contains(findingType, "cve") || strings.Contains(findingType, "vulnerability") {
		// Group by severity for CVE updates
		switch finding.Severity {
		case models.SeverityCritical, models.SeverityHigh:
			return "container-cve-critical"
		default:
			return "container-cve-updates"
		}
	}

	if strings.Contains(findingType, "config") || strings.Contains(findingType, "misconfiguration") {
		return "container-config"
	}

	return "container-generic"
}

// determineKubescapeStrategy categorizes Kubescape findings.
func (g *FindingGrouper) determineKubescapeStrategy(finding models.Finding) string {
	findingType := strings.ToLower(finding.Type)

	if strings.Contains(findingType, "security") && strings.Contains(findingType, "context") {
		return "kubernetes-security-context"
	}

	if strings.Contains(findingType, "network") || strings.Contains(findingType, "policy") {
		return "kubernetes-network-policy"
	}

	if strings.Contains(findingType, "rbac") || strings.Contains(findingType, "permission") {
		return "kubernetes-rbac"
	}

	if strings.Contains(findingType, "resource") || strings.Contains(findingType, "limit") {
		return "kubernetes-resources"
	}

	return "kubernetes-generic"
}

// determineCheckovStrategy categorizes Checkov findings.
func (g *FindingGrouper) determineCheckovStrategy(finding models.Finding) string {
	resource := strings.ToLower(finding.Resource)
	findingType := strings.ToLower(finding.Type)

	// Terraform findings - check both resource and type for terraform indicators
	if strings.Contains(resource, ".tf") || strings.Contains(resource, "aws_") || strings.Contains(findingType, "terraform") || strings.Contains(findingType, "ckv_aws") {
		if strings.Contains(findingType, "s3") || strings.Contains(resource, "s3") || (strings.Contains(findingType, "ckv_aws") && strings.Contains(findingType, "20")) {
			return "terraform-s3-public-access"
		} else if strings.Contains(findingType, "encryption") {
			return "terraform-encryption"
		}
		return "terraform-generic"
	}

	// Kubernetes findings
	if strings.Contains(resource, ".yaml") || strings.Contains(resource, ".yml") {
		return "kubernetes-generic"
	}

	// Docker findings
	if strings.Contains(resource, "dockerfile") {
		return "docker-security"
	}

	return "iac-generic"
}

// getRepositoryType maps strategy to repository type.
func (g *FindingGrouper) getRepositoryType(strategy string) string {
	switch {
	case strings.HasPrefix(strategy, "terraform-"):
		return RepoTypeTerraform
	case strings.HasPrefix(strategy, "kubernetes-"):
		return RepoTypeKubernetes
	case strings.HasPrefix(strategy, "docker-") || strings.HasPrefix(strategy, "container-"):
		return RepoTypeDocker
	case strings.HasPrefix(strategy, "aws-"):
		// AWS findings might be in CloudFormation or Terraform
		return RepoTypeTerraform // Default to Terraform
	case strings.Contains(strategy, "ansible"):
		return RepoTypeAnsible
	}
	return RepoTypeGeneric
}

// calculatePriority determines the priority of a remediation group.
func (g *FindingGrouper) calculatePriority(findings []models.Finding) int {
	// Count findings by severity
	severityCounts := make(map[string]int)
	for _, f := range findings {
		severityCounts[f.Severity]++
	}

	// Priority based on severity distribution
	switch {
	case severityCounts[models.SeverityCritical] > 0:
		return PriorityUrgent
	case severityCounts[models.SeverityHigh] > 2:
		return PriorityHigh
	case severityCounts[models.SeverityHigh] > 0:
		return PriorityMedium
	case severityCounts[models.SeverityMedium] > 0:
		return PriorityLow
	default:
		return PriorityDeferred
	}
}

// estimateEffort estimates the time required to implement a remediation.
func (g *FindingGrouper) estimateEffort(strategy string, findingCount int) time.Duration {
	// Base effort by strategy type
	baseEffort := g.getBaseEffort(strategy)

	// Scale by number of findings
	scaleFactor := 1.0
	switch {
	case findingCount > 50:
		scaleFactor = 3.0
	case findingCount > 20:
		scaleFactor = 2.0
	case findingCount > 10:
		scaleFactor = 1.5
	}

	return time.Duration(float64(baseEffort) * scaleFactor)
}

// getBaseEffort returns the base effort for a strategy.
func (g *FindingGrouper) getBaseEffort(strategy string) time.Duration {
	switch strategy {
	// Simple configuration changes
	case "terraform-s3-public-access", "terraform-s3-versioning":
		return 30 * time.Minute
	case "kubernetes-security-context", "kubernetes-resources":
		return 45 * time.Minute

	// Medium complexity changes
	case "terraform-rds-encryption", "terraform-s3-encryption":
		return 2 * time.Hour
	case "kubernetes-network-policy", "docker-security":
		return 90 * time.Minute

	// Complex changes
	case "terraform-iam-policy", "kubernetes-rbac":
		return 3 * time.Hour
	case "container-cve-critical":
		return 4 * time.Hour
	case "secrets-rotation":
		return 8 * time.Hour

	// Generic strategies
	default:
		return 2 * time.Hour
	}
}
