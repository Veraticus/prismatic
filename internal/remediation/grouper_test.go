package remediation

import (
	"testing"
	"time"

	"github.com/joshsymonds/prismatic/internal/enrichment"
	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/joshsymonds/prismatic/pkg/logger"
)

func TestFindingGrouper_GroupByRemediation(t *testing.T) {
	log := logger.NewMockLogger()
	grouper := NewFindingGrouper(nil, log)

	findings := []models.Finding{
		// S3 findings - should be grouped together
		{
			ID:       "s3-1",
			Scanner:  "prowler",
			Type:     "s3_bucket_public_read_access",
			Severity: models.SeverityCritical,
			Resource: "bucket-1",
		},
		{
			ID:       "s3-2",
			Scanner:  "prowler",
			Type:     "s3_bucket_public_write_access",
			Severity: models.SeverityHigh,
			Resource: "bucket-2",
		},
		{
			ID:       "s3-3",
			Scanner:  "checkov",
			Type:     "CKV_AWS_20",
			Severity: models.SeverityHigh,
			Resource: "aws_s3_bucket.test",
		},
		// RDS findings - different group
		{
			ID:       "rds-1",
			Scanner:  "prowler",
			Type:     "rds_instance_encryption_disabled",
			Severity: models.SeverityHigh,
			Resource: "db-instance-1",
		},
		// Kubernetes findings
		{
			ID:       "k8s-1",
			Scanner:  "kubescape",
			Type:     "missing_security_context",
			Severity: models.SeverityMedium,
			Resource: "deployment/app",
		},
		{
			ID:       "k8s-2",
			Scanner:  "kubescape",
			Type:     "missing_security_context",
			Severity: models.SeverityMedium,
			Resource: "deployment/api",
		},
	}

	groups := grouper.GroupByRemediation(findings, nil)

	// Debug: print all groups and their strategies
	t.Logf("Total groups: %d", len(groups))
	for i, group := range groups {
		t.Logf("Group %d: strategy=%s, findings=%d", i, group.Strategy, len(group.Findings))
		for _, f := range group.Findings {
			t.Logf("  - Finding: %s (scanner=%s, type=%s)", f.ID, f.Scanner, f.Type)
		}
	}

	// Should have at least 3 groups (S3, RDS, K8s)
	if len(groups) < 3 {
		t.Errorf("Expected at least 3 groups, got %d", len(groups))
	}

	// Find and verify S3 group
	var s3Group *Group
	for i, group := range groups {
		if group.Strategy == "terraform-s3-public-access" {
			s3Group = &groups[i]
			break
		}
	}

	if s3Group == nil {
		t.Fatal("S3 remediation group not found")
	}

	// S3 group should have 3 findings
	if len(s3Group.Findings) != 3 {
		t.Errorf("Expected 3 S3 findings, got %d", len(s3Group.Findings))
	}

	// Should have terraform repository type
	if s3Group.RepositoryType != RepoTypeTerraform {
		t.Errorf("Expected terraform repository type, got %s", s3Group.RepositoryType)
	}

	// Should have appropriate priority (critical finding present)
	if s3Group.Priority != PriorityUrgent {
		t.Errorf("Expected urgent priority, got %d", s3Group.Priority)
	}
}

func TestFindingGrouper_DetermineStrategy(t *testing.T) {
	log := logger.NewMockLogger()
	grouper := NewFindingGrouper(nil, log)

	testCases := []struct {
		name     string
		expected string
		finding  models.Finding
	}{
		{
			name: "Prowler S3 public access",
			finding: models.Finding{
				Scanner:  "prowler",
				Type:     "s3_bucket_public_access_enabled",
				Resource: "my-bucket",
			},
			expected: "terraform-s3-public-access",
		},
		{
			name: "Prowler S3 encryption",
			finding: models.Finding{
				Scanner:  "prowler",
				Type:     "s3_bucket_encryption_disabled",
				Resource: "my-bucket",
			},
			expected: "terraform-s3-encryption",
		},
		{
			name: "Prowler RDS encryption",
			finding: models.Finding{
				Scanner:  "prowler",
				Type:     "rds_instance_not_encrypted",
				Resource: "db-instance",
			},
			expected: "terraform-rds-encryption",
		},
		{
			name: "Trivy CVE critical",
			finding: models.Finding{
				Scanner:  "trivy",
				Type:     "CVE-2023-12345",
				Severity: models.SeverityCritical,
			},
			expected: "container-cve-critical",
		},
		{
			name: "Trivy CVE low",
			finding: models.Finding{
				Scanner:  "trivy",
				Type:     "CVE-2023-12345",
				Severity: models.SeverityLow,
			},
			expected: "container-cve-updates",
		},
		{
			name: "Kubescape security context",
			finding: models.Finding{
				Scanner: "kubescape",
				Type:    "missing_pod_security_context",
			},
			expected: "kubernetes-security-context",
		},
		{
			name: "Kubescape RBAC",
			finding: models.Finding{
				Scanner: "kubescape",
				Type:    "excessive_rbac_permissions",
			},
			expected: "kubernetes-rbac",
		},
		{
			name: "Checkov Terraform S3",
			finding: models.Finding{
				Scanner:  "checkov",
				Type:     "CKV_AWS_20",
				Resource: "aws_s3_bucket.test",
			},
			expected: "terraform-s3-public-access",
		},
		{
			name: "Nuclei web",
			finding: models.Finding{
				Scanner: "nuclei",
				Type:    "exposed-api-key",
			},
			expected: "web-configuration",
		},
		{
			name: "Gitleaks secrets",
			finding: models.Finding{
				Scanner: "gitleaks",
				Type:    "aws-access-key",
			},
			expected: "secrets-rotation",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			strategy := grouper.determineStrategy(tc.finding, nil)
			if strategy != tc.expected {
				t.Errorf("Expected strategy %s, got %s", tc.expected, strategy)
			}
		})
	}
}

func TestFindingGrouper_CalculatePriority(t *testing.T) {
	log := logger.NewMockLogger()
	grouper := NewFindingGrouper(nil, log)

	testCases := []struct {
		name     string
		findings []models.Finding
		expected int
	}{
		{
			name: "Critical findings = Urgent priority",
			findings: []models.Finding{
				{Severity: models.SeverityCritical},
				{Severity: models.SeverityHigh},
			},
			expected: PriorityUrgent,
		},
		{
			name: "Multiple high findings = High priority",
			findings: []models.Finding{
				{Severity: models.SeverityHigh},
				{Severity: models.SeverityHigh},
				{Severity: models.SeverityHigh},
			},
			expected: PriorityHigh,
		},
		{
			name: "Single high finding = Medium priority",
			findings: []models.Finding{
				{Severity: models.SeverityHigh},
				{Severity: models.SeverityMedium},
			},
			expected: PriorityMedium,
		},
		{
			name: "Only medium findings = Low priority",
			findings: []models.Finding{
				{Severity: models.SeverityMedium},
				{Severity: models.SeverityMedium},
			},
			expected: PriorityLow,
		},
		{
			name: "Only low/info findings = Deferred priority",
			findings: []models.Finding{
				{Severity: models.SeverityLow},
				{Severity: models.SeverityInfo},
			},
			expected: PriorityDeferred,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			priority := grouper.calculatePriority(tc.findings)
			if priority != tc.expected {
				t.Errorf("Expected priority %d, got %d", tc.expected, priority)
			}
		})
	}
}

func TestFindingGrouper_EstimateEffort(t *testing.T) {
	log := logger.NewMockLogger()
	grouper := NewFindingGrouper(nil, log)

	testCases := []struct {
		name          string
		strategy      string
		findingCount  int
		expectedRange [2]time.Duration
	}{
		{
			name:          "Simple S3 fix with few findings",
			strategy:      "terraform-s3-public-access",
			findingCount:  3,
			expectedRange: [2]time.Duration{25 * time.Minute, 35 * time.Minute},
		},
		{
			name:          "Simple S3 fix with many findings",
			strategy:      "terraform-s3-public-access",
			findingCount:  15,
			expectedRange: [2]time.Duration{40 * time.Minute, 50 * time.Minute},
		},
		{
			name:          "Complex IAM policy fix",
			strategy:      "terraform-iam-policy",
			findingCount:  5,
			expectedRange: [2]time.Duration{2 * time.Hour, 4 * time.Hour},
		},
		{
			name:          "Critical CVE updates",
			strategy:      "container-cve-critical",
			findingCount:  10,
			expectedRange: [2]time.Duration{3 * time.Hour, 5 * time.Hour},
		},
		{
			name:          "Secrets rotation",
			strategy:      "secrets-rotation",
			findingCount:  2,
			expectedRange: [2]time.Duration{7 * time.Hour, 9 * time.Hour},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			effort := grouper.estimateEffort(tc.strategy, tc.findingCount)
			if effort < tc.expectedRange[0] || effort > tc.expectedRange[1] {
				t.Errorf("Expected effort between %v and %v, got %v",
					tc.expectedRange[0], tc.expectedRange[1], effort)
			}
		})
	}
}

func TestFindingGrouper_WithEnrichments(t *testing.T) {
	log := logger.NewMockLogger()
	grouper := NewFindingGrouper(nil, log)

	findings := []models.Finding{
		{
			ID:       "finding-1",
			Scanner:  "prowler",
			Type:     "s3_bucket_public_access",
			Severity: models.SeverityHigh,
			Resource: "bucket-1",
		},
	}

	enrichments := map[string]*enrichment.FindingEnrichment{
		"finding-1": {
			FindingID: "finding-1",
			Analysis: enrichment.Analysis{
				BusinessImpact:   "Customer data exposed",
				TechnicalDetails: "Public S3 bucket exposing customer data. Compliance: PCI-DSS, HIPAA",
				PriorityScore:    9.0,
			},
		},
	}

	groups := grouper.GroupByRemediation(findings, enrichments)

	if len(groups) != 1 {
		t.Fatalf("Expected 1 group, got %d", len(groups))
	}

	// Enrichment data should be available but not affect grouping
	if groups[0].Strategy != "terraform-s3-public-access" {
		t.Errorf("Expected terraform-s3-public-access strategy, got %s", groups[0].Strategy)
	}
}
