package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/joshsymonds/prismatic/internal/config"
	"github.com/joshsymonds/prismatic/internal/enrichment"
	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/joshsymonds/prismatic/internal/remediation"
	"github.com/joshsymonds/prismatic/pkg/logger"
)

func TestRemediationReporter_Generate(t *testing.T) {
	// Create test logger
	log := logger.NewMockLogger()

	// Create test findings
	findings := []models.Finding{
		{
			ID:          "s3-001",
			Scanner:     "prowler",
			Type:        "s3_bucket_public_access",
			Severity:    models.SeverityCritical,
			Title:       "S3 bucket allows public access",
			Resource:    "my-public-bucket",
			Location:    "us-east-1",
			Description: "S3 bucket has public read access enabled",
			Remediation: "Disable public access",
		},
		{
			ID:          "s3-002",
			Scanner:     "prowler",
			Type:        "s3_bucket_public_access",
			Severity:    models.SeverityHigh,
			Title:       "S3 bucket allows public access",
			Resource:    "another-public-bucket",
			Location:    "us-east-1",
			Description: "S3 bucket has public read access enabled",
			Remediation: "Disable public access",
		},
		{
			ID:          "k8s-001",
			Scanner:     "kubescape",
			Type:        "missing_security_context",
			Severity:    models.SeverityHigh,
			Title:       "Pod missing security context",
			Resource:    "deployment/api-gateway",
			Location:    "default",
			Description: "Pod spec does not define security context",
			Remediation: "Add security context",
		},
	}

	// Create test enrichments
	enrichments := map[string]*enrichment.FindingEnrichment{
		"s3-001": {
			FindingID: "s3-001",
			Analysis: enrichment.Analysis{
				BusinessImpact:   "Customer PII exposed",
				TechnicalDetails: "S3 bucket has public read access enabled. Compliance: PCI-DSS 3.4, HIPAA 164.312(a)(1)",
				PriorityScore:    9.5,
			},
		},
		"k8s-001": {
			FindingID: "k8s-001",
			Analysis: enrichment.Analysis{
				BusinessImpact:   "Container could run as root",
				TechnicalDetails: "Pod spec lacks security context. Compliance: CIS Kubernetes Benchmark 5.3.2",
				PriorityScore:    7.0,
			},
		},
	}

	// Create test metadata
	metadata := &models.ScanMetadata{
		ID:          "2024-01-15-133214",
		StartTime:   time.Now().Add(-time.Hour),
		EndTime:     time.Now(),
		ClientName:  "test-client",
		Environment: "production",
	}

	// Create reporter
	cfg := &config.Config{}
	reporter := NewRemediationReporter(cfg, log)

	// Generate report
	outputPath := filepath.Join(t.TempDir(), "remediation.yaml")
	err := reporter.Generate(findings, enrichments, metadata, outputPath)
	if err != nil {
		t.Fatalf("Failed to generate remediation report: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Fatal("Output file was not created")
	}

	// Load and verify manifest
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	var manifest remediation.Manifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("Failed to parse YAML manifest: %v", err)
	}

	// Verify manifest structure
	if manifest.ManifestVersion != "1.0" {
		t.Errorf("Expected manifest version 1.0, got %s", manifest.ManifestVersion)
	}

	if manifest.ScanID != metadata.ID {
		t.Errorf("Expected scan ID %s, got %s", metadata.ID, manifest.ScanID)
	}

	// Should have 2 remediations (S3 findings grouped, K8s separate)
	if len(manifest.Remediations) != 2 {
		t.Errorf("Expected 2 remediations, got %d", len(manifest.Remediations))
	}

	// Verify S3 remediation
	var s3Rem *remediation.Remediation
	for i, rem := range manifest.Remediations {
		if strings.Contains(rem.Title, "S3") {
			s3Rem = &manifest.Remediations[i]
			break
		}
	}

	if s3Rem == nil {
		t.Fatal("S3 remediation not found")
	}

	// Should reference both S3 findings
	if len(s3Rem.FindingRefs) != 2 {
		t.Errorf("Expected 2 finding refs for S3 remediation, got %d", len(s3Rem.FindingRefs))
	}

	// Should have critical severity (highest from group)
	if s3Rem.Severity != models.SeverityCritical {
		t.Errorf("Expected critical severity, got %s", s3Rem.Severity)
	}

	// Should have terraform repository type
	if s3Rem.Target.RepositoryType != remediation.RepoTypeTerraform {
		t.Errorf("Expected terraform repository type, got %s", s3Rem.Target.RepositoryType)
	}

	// Should have implementation details
	if s3Rem.Implementation.LLMInstructions == "" {
		t.Error("Expected LLM instructions")
	}

	if len(s3Rem.Implementation.CodeChanges) == 0 {
		t.Error("Expected code changes")
	}

	// Should have validation steps
	if len(s3Rem.Validation) == 0 {
		t.Error("Expected validation steps")
	}
}

func TestRemediationReporter_SuppressedFindings(t *testing.T) {
	log := logger.NewMockLogger()

	findings := []models.Finding{
		{
			ID:         "finding-1",
			Scanner:    "prowler",
			Type:       "s3_bucket_public_access",
			Severity:   models.SeverityCritical,
			Title:      "S3 bucket allows public access",
			Resource:   "bucket-1",
			Suppressed: true, // This finding is suppressed
		},
		{
			ID:         "finding-2",
			Scanner:    "prowler",
			Type:       "s3_bucket_public_access",
			Severity:   models.SeverityCritical,
			Title:      "S3 bucket allows public access",
			Resource:   "bucket-2",
			Suppressed: false,
		},
	}

	metadata := &models.ScanMetadata{
		ID: "test-scan",
	}

	reporter := NewRemediationReporter(nil, log)
	outputPath := filepath.Join(t.TempDir(), "remediation.yaml")

	err := reporter.Generate(findings, nil, metadata, outputPath)
	if err != nil {
		t.Fatalf("Failed to generate report: %v", err)
	}

	// Load manifest
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read output: %v", err)
	}

	var manifest remediation.Manifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("Failed to parse manifest: %v", err)
	}

	// Should only have 1 remediation (suppressed finding excluded)
	if len(manifest.Remediations) != 1 {
		t.Errorf("Expected 1 remediation, got %d", len(manifest.Remediations))
	}

	if len(manifest.Remediations) > 0 {
		// Should only reference the non-suppressed finding
		if len(manifest.Remediations[0].FindingRefs) != 1 {
			t.Errorf("Expected 1 finding ref, got %d", len(manifest.Remediations[0].FindingRefs))
		}

		if manifest.Remediations[0].FindingRefs[0] != "finding-2" {
			t.Errorf("Expected finding-2, got %s", manifest.Remediations[0].FindingRefs[0])
		}
	}
}

func TestRemediationReporter_EmptyFindings(t *testing.T) {
	log := logger.NewMockLogger()
	reporter := NewRemediationReporter(nil, log)

	metadata := &models.ScanMetadata{
		ID: "empty-scan",
	}

	outputPath := filepath.Join(t.TempDir(), "empty.yaml")
	err := reporter.Generate([]models.Finding{}, nil, metadata, outputPath)

	if err != nil {
		t.Fatalf("Failed to generate empty report: %v", err)
	}

	// Should create an empty manifest
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read output: %v", err)
	}

	var manifest remediation.Manifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("Failed to parse manifest: %v", err)
	}

	if len(manifest.Remediations) != 0 {
		t.Errorf("Expected 0 remediations, got %d", len(manifest.Remediations))
	}

	if manifest.Metadata.TotalFindings != 0 {
		t.Errorf("Expected 0 total findings, got %d", manifest.Metadata.TotalFindings)
	}
}

func TestRemediationReporter_PriorityOrdering(t *testing.T) {
	log := logger.NewMockLogger()

	findings := []models.Finding{
		// Low priority finding
		{
			ID:       "low-1",
			Scanner:  "trivy",
			Type:     "container_cve",
			Severity: models.SeverityLow,
			Title:    "Low severity CVE",
			Resource: "image:latest",
		},
		// Critical priority finding
		{
			ID:       "critical-1",
			Scanner:  "prowler",
			Type:     "s3_bucket_public_access",
			Severity: models.SeverityCritical,
			Title:    "Critical S3 exposure",
			Resource: "critical-bucket",
		},
		// High priority finding
		{
			ID:       "high-1",
			Scanner:  "kubescape",
			Type:     "missing_security_context",
			Severity: models.SeverityHigh,
			Title:    "High severity finding",
			Resource: "deployment/app",
		},
	}

	metadata := &models.ScanMetadata{
		ID: "priority-test",
	}

	reporter := NewRemediationReporter(nil, log)
	outputPath := filepath.Join(t.TempDir(), "priority.yaml")

	err := reporter.Generate(findings, nil, metadata, outputPath)
	if err != nil {
		t.Fatalf("Failed to generate report: %v", err)
	}

	// Load manifest
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read output: %v", err)
	}

	var manifest remediation.Manifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("Failed to parse manifest: %v", err)
	}

	// Verify ordering by priority/severity
	if len(manifest.Remediations) < 2 {
		t.Fatal("Expected at least 2 remediations")
	}

	// First should be the critical finding
	if manifest.Remediations[0].Severity != models.SeverityCritical {
		t.Errorf("First remediation should be critical, got %s", manifest.Remediations[0].Severity)
	}

	// Verify priority scores are set
	for i, rem := range manifest.Remediations {
		if rem.Priority == 0 {
			t.Errorf("Remediation %d has no priority set", i)
		}
	}
}

func TestRemediationReporter_YAMLFormat(t *testing.T) {
	log := logger.NewMockLogger()

	findings := []models.Finding{
		{
			ID:          "test-1",
			Scanner:     "checkov",
			Type:        "terraform_s3_public_access",
			Severity:    models.SeverityHigh,
			Title:       "S3 bucket public access",
			Resource:    "aws_s3_bucket.test",
			Location:    "main.tf:10",
			Description: "S3 bucket allows public access",
			Remediation: "Add public access block",
		},
	}

	enrichments := map[string]*enrichment.FindingEnrichment{
		"test-1": {
			FindingID: "test-1",
			Analysis: enrichment.Analysis{
				BusinessImpact:   "Data exposure risk",
				TechnicalDetails: "S3 bucket allows public access. Compliance: SOC2, ISO27001",
				PriorityScore:    8.0,
			},
		},
	}

	metadata := &models.ScanMetadata{
		ID: "yaml-test",
	}

	reporter := NewRemediationReporter(nil, log)
	outputPath := filepath.Join(t.TempDir(), "format.yaml")

	err := reporter.Generate(findings, enrichments, metadata, outputPath)
	if err != nil {
		t.Fatalf("Failed to generate report: %v", err)
	}

	// Read and verify YAML structure
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read output: %v", err)
	}

	// Verify it's valid YAML
	var rawData map[string]interface{}
	if err := yaml.Unmarshal(data, &rawData); err != nil {
		t.Fatalf("Invalid YAML generated: %v", err)
	}

	// Verify key fields are present
	yamlStr := string(data)
	expectedFields := []string{
		"manifest_version:",
		"generated_at:",
		"scan_id:",
		"metadata:",
		"remediations:",
		"finding_refs:",
		"target:",
		"implementation:",
		"validation:",
	}

	for _, field := range expectedFields {
		if !strings.Contains(yamlStr, field) {
			t.Errorf("Expected field %s not found in YAML", field)
		}
	}
}
