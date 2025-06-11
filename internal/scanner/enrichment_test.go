// Package scanner contains tests for enrichment functionality that has been moved to the report package.
// The tests are preserved here for reference but are commented out.
package scanner

/*
import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/joshsymonds/prismatic/internal/config"
	"github.com/joshsymonds/prismatic/internal/models"
)

func TestEnrichFindingsWithBusinessContext(t *testing.T) {
	tests := []struct {
		config                *config.Config
		validateFirst         func(t *testing.T, f *models.Finding)
		name                  string
		findings              []models.Finding
		expectedEnrichedCount int
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
			expectedEnrichedCount: 2, // 2 findings have matching metadata
			validateFirst: func(t *testing.T, f *models.Finding) {
				t.Helper()
				assert.Equal(t, "finding-1", f.ID)
				require.NotNil(t, f.BusinessContext)
				assert.Equal(t, "data-team", f.BusinessContext.Owner)
				assert.Equal(t, "confidential", f.BusinessContext.DataClassification)
				assert.Equal(t, "Critical data storage", f.BusinessContext.BusinessImpact)
				assert.Contains(t, f.BusinessContext.ComplianceImpact, "SOC2")
				assert.Contains(t, f.BusinessContext.ComplianceImpact, "GDPR")
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
			expectedEnrichedCount: 0,
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
			expectedEnrichedCount: 1, // 1 finding has matching metadata
			validateFirst: func(t *testing.T, f *models.Finding) {
				t.Helper()
				require.NotNil(t, f.BusinessContext)
				assert.Equal(t, "database-team", f.BusinessContext.Owner)
				assert.Equal(t, "restricted", f.BusinessContext.DataClassification)
				// BusinessImpact and ComplianceImpact should be empty
				assert.Empty(t, f.BusinessContext.BusinessImpact)
				assert.Empty(t, f.BusinessContext.ComplianceImpact)
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
			orch.EnrichFindings(metadata)

			// Count enriched findings
			enrichedCount := 0
			for _, result := range metadata.Results {
				for _, f := range result.Findings {
					if f.BusinessContext != nil {
						enrichedCount++
					}
				}
			}

			// Verify count
			assert.Equal(t, tt.expectedEnrichedCount, enrichedCount)

			// Validate enriched findings with business context
			if tt.expectedEnrichedCount > 0 && tt.validateFirst != nil {
				// Find the first finding with business context
				for _, result := range metadata.Results {
					for i := range result.Findings {
						f := &result.Findings[i]
						if f.BusinessContext != nil && f.BusinessContext.Owner != "" {
							tt.validateFirst(t, f)
							return
						}
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

	// Verify the process works - mock findings won't match our enrichment config
	assert.NotNil(t, metadata)
	assert.NotEmpty(t, metadata.Results)
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

	orch.EnrichFindings(metadata)

	// Should enrich both suppressed and active findings
	enrichedCount := 0
	for _, result := range metadata.Results {
		for _, f := range result.Findings {
			if f.BusinessContext != nil {
				enrichedCount++
			}
		}
	}
	assert.Equal(t, 2, enrichedCount)

	// Verify suppressed finding retains suppression status
	for _, result := range metadata.Results {
		for _, f := range result.Findings {
			if f.ID == "finding-1" {
				assert.True(t, f.Suppressed)
				assert.Equal(t, "test-team", f.BusinessContext.Owner)
			}
		}
	}
}
*/
