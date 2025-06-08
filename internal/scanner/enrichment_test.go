package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Veraticus/prismatic/internal/config"
	"github.com/Veraticus/prismatic/internal/models"
)

func TestEnrichFindingsWithBusinessContext(t *testing.T) {
	tests := []struct {
		config           *config.Config
		validateFirst    func(t *testing.T, ef models.EnrichedFinding)
		name             string
		findings         []models.Finding
		expectedEnriched int
	}{
		{
			name: "enrich findings with metadata",
			config: &config.Config{
				Client: config.ClientConfig{
					Name:        "Test Corp",
					Environment: "Production",
				},
				MetadataEnrichment: config.MetadataEnrichment{
					Resources: map[string]config.ResourceMetadata{
						"arn:aws:s3:::test-bucket": {
							Owner:              "data-team",
							DataClassification: "confidential",
							BusinessImpact:     "Critical data storage",
							ComplianceImpact:   []string{"SOC2", "GDPR"},
						},
						"test-api:latest": {
							Owner:              "api-team",
							DataClassification: "internal",
							BusinessImpact:     "Core API service",
							ComplianceImpact:   []string{"PCI-DSS"},
						},
					},
				},
			},
			findings: []models.Finding{
				{
					ID:       "finding-1",
					Scanner:  "prowler",
					Type:     "aws-misconfiguration",
					Severity: "high",
					Title:    "S3 bucket publicly accessible",
					Resource: "arn:aws:s3:::test-bucket",
				},
				{
					ID:       "finding-2",
					Scanner:  "trivy",
					Type:     "vulnerability",
					Severity: "critical",
					Title:    "Critical CVE in container",
					Resource: "test-api:latest",
				},
				{
					ID:       "finding-3",
					Scanner:  "nuclei",
					Type:     "web-vulnerability",
					Severity: "medium",
					Title:    "Exposed admin panel",
					Resource: "https://test.example.com",
				},
			},
			expectedEnriched: 3, // All findings are enriched, 2 have metadata
			validateFirst: func(t *testing.T, ef models.EnrichedFinding) {
				assert.Equal(t, "finding-1", ef.ID)
				assert.Equal(t, "data-team", ef.BusinessContext.Owner)
				assert.Equal(t, "confidential", ef.BusinessContext.DataClassification)
				assert.Equal(t, "Critical data storage", ef.BusinessContext.BusinessImpact)
				assert.Contains(t, ef.BusinessContext.ComplianceImpact, "SOC2")
				assert.Contains(t, ef.BusinessContext.ComplianceImpact, "GDPR")
			},
		},
		{
			name: "no enrichment configured",
			config: &config.Config{
				Client: config.ClientConfig{
					Name:        "Test Corp",
					Environment: "Production",
				},
			},
			findings: []models.Finding{
				{
					ID:       "finding-1",
					Scanner:  "prowler",
					Type:     "aws-misconfiguration",
					Severity: "high",
					Title:    "S3 bucket publicly accessible",
					Resource: "arn:aws:s3:::test-bucket",
				},
			},
			expectedEnriched: 0,
		},
		{
			name: "partial enrichment",
			config: &config.Config{
				Client: config.ClientConfig{
					Name:        "Test Corp",
					Environment: "Production",
				},
				MetadataEnrichment: config.MetadataEnrichment{
					Resources: map[string]config.ResourceMetadata{
						"prod-db": {
							Owner:              "database-team",
							DataClassification: "restricted",
						},
					},
				},
			},
			findings: []models.Finding{
				{
					ID:       "finding-1",
					Scanner:  "prowler",
					Type:     "aws-misconfiguration",
					Severity: "high",
					Title:    "RDS encryption disabled",
					Resource: "prod-db",
				},
				{
					ID:       "finding-2",
					Scanner:  "prowler",
					Type:     "aws-misconfiguration",
					Severity: "medium",
					Title:    "S3 versioning disabled",
					Resource: "logs-bucket",
				},
			},
			expectedEnriched: 2, // All findings enriched, 1 has metadata
			validateFirst: func(t *testing.T, ef models.EnrichedFinding) {
				assert.Equal(t, "database-team", ef.BusinessContext.Owner)
				assert.Equal(t, "restricted", ef.BusinessContext.DataClassification)
				// BusinessImpact and ComplianceImpact should be empty
				assert.Empty(t, ef.BusinessContext.BusinessImpact)
				assert.Empty(t, ef.BusinessContext.ComplianceImpact)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create orchestrator
			orch := NewOrchestrator(tt.config, "/tmp", false)

			// Create scan metadata with findings
			metadata := &models.ScanMetadata{
				StartTime: time.Now(),
				EndTime:   time.Now(),
				Results: map[string]*models.ScanResult{
					"test": {
						Scanner:  "test",
						Findings: tt.findings,
					},
				},
			}

			// Enrich findings
			enrichedFindings := orch.EnrichFindings(metadata)

			// Verify count
			assert.Len(t, enrichedFindings, tt.expectedEnriched)

			// Validate enriched findings with business context
			if tt.expectedEnriched > 0 && tt.validateFirst != nil {
				// Find the first finding with business context
				for _, ef := range enrichedFindings {
					if ef.BusinessContext.Owner != "" {
						tt.validateFirst(t, ef)
						break
					}
				}
			}
		})
	}
}

func TestEnrichmentIntegration(t *testing.T) {
	// Create a complete test scenario
	cfg := &config.Config{
		Client: config.ClientConfig{
			Name:        "ACME Corp",
			Environment: "Production",
		},
		AWS: &config.AWSConfig{
			Profiles: []string{"default"},
		},
		Docker: &config.DockerConfig{
			Containers: []string{"api:latest"},
		},
		MetadataEnrichment: config.MetadataEnrichment{
			Resources: map[string]config.ResourceMetadata{
				"arn:aws:s3:::acme-data": {
					Owner:              "data-team",
					DataClassification: "confidential",
					BusinessImpact:     "Customer data storage",
					ComplianceImpact:   []string{"GDPR", "CCPA"},
				},
				"api:latest": {
					Owner:              "platform-team",
					DataClassification: "internal",
					BusinessImpact:     "Main API service",
					ComplianceImpact:   []string{"SOC2"},
				},
			},
		},
	}

	// Create orchestrator
	orch := NewOrchestrator(cfg, "/tmp", true) // Use mock scanners

	// Initialize scanners
	err := orch.InitializeScanners([]string{"prowler", "trivy"})
	require.NoError(t, err)

	// Run scans
	ctx := context.Background()
	metadata, err := orch.RunScans(ctx)
	require.NoError(t, err)

	// Verify enriched findings were created
	assert.NotEmpty(t, metadata.EnrichedFindings)

	// Since mock findings don't match our enrichment config, just verify the process works
	// In a real scenario, findings would match the configured resources
}

func TestEnrichmentWithSuppression(t *testing.T) {
	cfg := &config.Config{
		Client: config.ClientConfig{
			Name:        "Test Corp",
			Environment: "Production",
		},
		Suppressions: config.SuppressionConfig{
			Scanners: map[string][]string{
				"prowler": {"check-123"},
			},
		},
		MetadataEnrichment: config.MetadataEnrichment{
			Resources: map[string]config.ResourceMetadata{
				"test-resource": {
					Owner:              "test-team",
					DataClassification: "public",
				},
			},
		},
	}

	orch := NewOrchestrator(cfg, "/tmp", false)

	metadata := &models.ScanMetadata{
		StartTime: time.Now(),
		EndTime:   time.Now(),
		Results: map[string]*models.ScanResult{
			"prowler": {
				Scanner: "prowler",
				Findings: []models.Finding{
					{
						ID:         "finding-1",
						Scanner:    "prowler",
						Type:       "check-123",
						Severity:   "high",
						Title:      "Suppressed finding",
						Resource:   "test-resource",
						Suppressed: true,
					},
					{
						ID:       "finding-2",
						Scanner:  "prowler",
						Type:     "check-456",
						Severity: "medium",
						Title:    "Active finding",
						Resource: "test-resource",
					},
				},
			},
		},
	}

	enrichedFindings := orch.EnrichFindings(metadata)

	// Should enrich both suppressed and active findings
	assert.Len(t, enrichedFindings, 2)

	// Verify suppressed finding retains suppression status
	for _, ef := range enrichedFindings {
		if ef.ID == "finding-1" {
			assert.True(t, ef.Suppressed)
			assert.Equal(t, "test-team", ef.BusinessContext.Owner)
		}
	}
}
