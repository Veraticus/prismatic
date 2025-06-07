package scanner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Veraticus/prismatic/internal/config"
	"github.com/Veraticus/prismatic/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOrchestrator(t *testing.T) {
	cfg := &config.Config{
		Client: config.ClientConfig{
			Name:        "test-client",
			Environment: "test",
		},
	}

	orch := NewOrchestrator(cfg, "/tmp/output", false)
	assert.NotNil(t, orch)
	assert.Equal(t, cfg, orch.config)
	assert.Equal(t, "/tmp/output", orch.outputDir)
	assert.False(t, orch.useMock)
	assert.Empty(t, orch.scanners)
}

func TestDetermineScanners(t *testing.T) {
	tests := []struct {
		name         string
		config       *config.Config
		onlyScanners []string
		expected     []string
	}{
		{
			name:         "only scanners specified",
			config:       &config.Config{},
			onlyScanners: []string{"trivy", "prowler"},
			expected:     []string{"trivy", "prowler"},
		},
		{
			name: "aws config present",
			config: &config.Config{
				AWS: &config.AWSConfig{
					Profiles: []string{"default"},
				},
			},
			onlyScanners: []string{},
			expected:     []string{"prowler", "gitleaks", "checkov"},
		},
		{
			name: "docker config present",
			config: &config.Config{
				Docker: &config.DockerConfig{
					Containers: []string{"nginx:latest"},
				},
			},
			onlyScanners: []string{},
			expected:     []string{"trivy", "gitleaks", "checkov"},
		},
		{
			name: "kubernetes config present",
			config: &config.Config{
				Kubernetes: &config.KubernetesConfig{
					Contexts: []string{"default"},
				},
			},
			onlyScanners: []string{},
			expected:     []string{"kubescape", "gitleaks", "checkov"},
		},
		{
			name: "endpoints present",
			config: &config.Config{
				Endpoints: []string{"https://example.com"},
			},
			onlyScanners: []string{},
			expected:     []string{"nuclei", "gitleaks", "checkov"},
		},
		{
			name: "all configs present",
			config: &config.Config{
				AWS: &config.AWSConfig{
					Profiles: []string{"default"},
				},
				Docker: &config.DockerConfig{
					Containers: []string{"nginx:latest"},
				},
				Kubernetes: &config.KubernetesConfig{
					Contexts: []string{"default"},
				},
				Endpoints: []string{"https://example.com"},
			},
			onlyScanners: []string{},
			expected:     []string{"prowler", "trivy", "kubescape", "nuclei", "gitleaks", "checkov"},
		},
		{
			name:         "no config",
			config:       &config.Config{},
			onlyScanners: []string{},
			expected:     []string{"gitleaks", "checkov"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orch := NewOrchestrator(tt.config, "/tmp", false)
			result := orch.determineScanners(tt.onlyScanners)
			assert.ElementsMatch(t, tt.expected, result)
		})
	}
}

func TestInitializeScanners(t *testing.T) {
	cfg := &config.Config{
		AWS: &config.AWSConfig{
			Profiles: []string{"default"},
		},
	}

	// Test with mock scanners
	orch := NewOrchestrator(cfg, "/tmp", true)
	err := orch.InitializeScanners([]string{"prowler", "trivy"})
	require.NoError(t, err)
	assert.Len(t, orch.scanners, 2)

	// Verify scanner names
	names := []string{}
	for _, s := range orch.scanners {
		names = append(names, s.Name())
	}
	assert.ElementsMatch(t, []string{"mock-prowler", "mock-trivy"}, names)

	// Test with no scanners
	orch2 := NewOrchestrator(&config.Config{}, "/tmp", false)
	err = orch2.InitializeScanners([]string{})
	assert.NoError(t, err)                           // Gitleaks and Trivy are always available now
	assert.GreaterOrEqual(t, len(orch2.scanners), 1) // At least gitleaks should initialize

	// Test with real scanners (should initialize Prowler, Trivy and Gitleaks)
	orch3 := NewOrchestrator(cfg, "/tmp", false)
	err = orch3.InitializeScanners([]string{"prowler", "trivy", "gitleaks"})
	assert.NoError(t, err)           // All three should be initialized
	assert.Len(t, orch3.scanners, 3) // Prowler, Trivy and Gitleaks are implemented

	// Check scanner names
	scannerNames := []string{}
	for _, s := range orch3.scanners {
		scannerNames = append(scannerNames, s.Name())
	}
	assert.ElementsMatch(t, []string{"prowler", "trivy", "gitleaks"}, scannerNames)
}

func TestProcessResult(t *testing.T) {
	cfg := &config.Config{
		Suppressions: config.SuppressionConfig{
			Global: config.GlobalSuppressions{
				DateBefore: "2025-01-01",
			},
			Scanners: map[string][]string{
				"test-scanner": {"CVE-2021-12345"},
			},
		},
		SeverityOverrides: map[string]string{
			"TEST-001": "low",
		},
	}

	orch := NewOrchestrator(cfg, "/tmp", false)
	metadata := &models.ScanMetadata{
		Results: make(map[string]*models.ScanResult),
		Summary: models.ScanSummary{
			BySeverity: make(map[string]int),
			ByScanner:  make(map[string]int),
		},
	}

	// Create test date after the suppression cutoff
	testDate, _ := time.Parse("2006-01-02", "2025-06-01")

	result := &models.ScanResult{
		Scanner: "test-scanner",
		Findings: []models.Finding{
			{
				ID:             "finding-1",
				Scanner:        "test-scanner",
				Type:           "CVE-2021-12345",
				Severity:       "high",
				Title:          "Suppressed Finding",
				Resource:       "resource-1",
				DiscoveredDate: testDate, // After cutoff, so date suppression won't apply
			},
			{
				ID:             "finding-2",
				Scanner:        "test-scanner",
				Type:           "TEST-001",
				Severity:       "critical",
				Title:          "Override Severity",
				Resource:       "resource-2",
				DiscoveredDate: testDate,
			},
			{
				ID:             "finding-3",
				Scanner:        "test-scanner",
				Type:           "NORMAL-001",
				Severity:       "medium",
				Title:          "Normal Finding",
				Resource:       "resource-3",
				DiscoveredDate: testDate,
			},
			{
				// Invalid finding - missing required fields
				ID:             "finding-4",
				Scanner:        "test-scanner",
				Type:           "INVALID",
				DiscoveredDate: testDate,
				// Missing severity, title, resource
			},
		},
	}

	orch.processResult(result, metadata)

	// Check results
	assert.Contains(t, metadata.Results, "test-scanner")
	processedResult := metadata.Results["test-scanner"]
	assert.Len(t, processedResult.Findings, 3) // Invalid finding should be skipped

	// Check suppression
	assert.True(t, processedResult.Findings[0].Suppressed)
	assert.Equal(t, "Finding type CVE-2021-12345 is suppressed for test-scanner scanner", processedResult.Findings[0].SuppressionReason)

	// Check severity override
	assert.Equal(t, "low", processedResult.Findings[1].Severity)
	assert.Equal(t, "critical", processedResult.Findings[1].OriginalSeverity)

	// Check summary
	assert.Equal(t, 1, metadata.Summary.SuppressedCount)
	assert.Equal(t, 2, metadata.Summary.TotalFindings) // Suppressed findings don't count
	assert.Equal(t, 1, metadata.Summary.BySeverity["low"])
	assert.Equal(t, 1, metadata.Summary.BySeverity["medium"])
	assert.Equal(t, 3, metadata.Summary.ByScanner["test-scanner"])
}

func TestRunScans(t *testing.T) {
	cfg := &config.Config{
		Client: config.ClientConfig{
			Name:        "test-client",
			Environment: "test-env",
		},
	}

	// Create test scanners
	successScanner := &mockTestScanner{
		BaseScanner: *NewBaseScanner("success-scanner", Config{}),
		scanFunc: func(ctx context.Context) (*models.ScanResult, error) {
			return &models.ScanResult{
				Scanner:   "success-scanner",
				StartTime: time.Now(),
				EndTime:   time.Now(),
				Findings: []models.Finding{
					{
						ID:       "finding-1",
						Scanner:  "success-scanner",
						Type:     "test-type",
						Severity: "high",
						Title:    "Test Finding",
						Resource: "test-resource",
					},
				},
			}, nil
		},
	}

	failScanner := &mockTestScanner{
		BaseScanner: *NewBaseScanner("fail-scanner", Config{}),
		scanFunc: func(ctx context.Context) (*models.ScanResult, error) {
			return nil, errors.New("scanner failed")
		},
	}

	slowScanner := &mockTestScanner{
		BaseScanner: *NewBaseScanner("slow-scanner", Config{}),
		scanFunc: func(ctx context.Context) (*models.ScanResult, error) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(100 * time.Millisecond):
				return &models.ScanResult{
					Scanner:   "slow-scanner",
					StartTime: time.Now(),
					EndTime:   time.Now(),
					Findings:  []models.Finding{},
				}, nil
			}
		},
	}

	orch := NewOrchestrator(cfg, "/tmp", false)
	orch.scanners = []Scanner{successScanner, failScanner, slowScanner}

	ctx := context.Background()
	metadata, err := orch.RunScans(ctx)
	require.NoError(t, err)

	// Verify metadata
	assert.Equal(t, "test-client", metadata.ClientName)
	assert.Equal(t, "test-env", metadata.Environment)
	assert.NotZero(t, metadata.StartTime)
	assert.NotZero(t, metadata.EndTime)
	assert.True(t, metadata.EndTime.After(metadata.StartTime))
	assert.ElementsMatch(t, []string{"success-scanner", "fail-scanner", "slow-scanner"}, metadata.Scanners)

	// Verify results
	assert.Len(t, metadata.Results, 3)

	// Check success scanner
	assert.Contains(t, metadata.Results, "success-scanner")
	assert.Empty(t, metadata.Results["success-scanner"].Error)
	assert.Len(t, metadata.Results["success-scanner"].Findings, 1)

	// Check fail scanner
	assert.Contains(t, metadata.Results, "fail-scanner")
	assert.Equal(t, "scanner failed", metadata.Results["fail-scanner"].Error)
	assert.Empty(t, metadata.Results["fail-scanner"].Findings)

	// Check slow scanner
	assert.Contains(t, metadata.Results, "slow-scanner")
	assert.Empty(t, metadata.Results["slow-scanner"].Error)

	// Verify summary
	assert.Equal(t, 1, metadata.Summary.TotalFindings)
	assert.Equal(t, 1, metadata.Summary.BySeverity["high"])
	assert.ElementsMatch(t, []string{"fail-scanner"}, metadata.Summary.FailedScanners)
}

func TestRunScansWithContext(t *testing.T) {
	cfg := &config.Config{
		Client: config.ClientConfig{
			Name:        "test-client",
			Environment: "test-env",
		},
	}

	// Create a scanner that respects context cancellation
	contextScanner := &mockTestScanner{
		BaseScanner: *NewBaseScanner("context-scanner", Config{}),
		scanFunc: func(ctx context.Context) (*models.ScanResult, error) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(5 * time.Second):
				return &models.ScanResult{
					Scanner:  "context-scanner",
					Findings: []models.Finding{},
				}, nil
			}
		},
	}

	orch := NewOrchestrator(cfg, "/tmp", false)
	orch.scanners = []Scanner{contextScanner}

	// Cancel context immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	metadata, err := orch.RunScans(ctx)
	require.NoError(t, err)

	// Verify scanner failed due to context cancellation
	assert.Contains(t, metadata.Results, "context-scanner")
	assert.Contains(t, metadata.Results["context-scanner"].Error, "context canceled")
	assert.Contains(t, metadata.Summary.FailedScanners, "context-scanner")
}

func TestGetScannerNames(t *testing.T) {
	orch := NewOrchestrator(&config.Config{}, "/tmp", false)

	// Test empty
	assert.Empty(t, orch.getScannerNames())

	// Add scanners
	orch.scanners = []Scanner{
		NewMockScanner("scanner1", Config{}),
		NewMockScanner("scanner2", Config{}),
		NewMockScanner("scanner3", Config{}),
	}

	names := orch.getScannerNames()
	assert.ElementsMatch(t, []string{"mock-scanner1", "mock-scanner2", "mock-scanner3"}, names)
}

func TestGetKubescapeConfig(t *testing.T) {
	tests := []struct {
		name               string
		config             *config.Config
		expectedContexts   []string
		expectedNamespaces []string
	}{
		{
			name:               "no kubernetes config",
			config:             &config.Config{},
			expectedContexts:   nil,
			expectedNamespaces: nil,
		},
		{
			name: "with kubernetes config",
			config: &config.Config{
				Kubernetes: &config.KubernetesConfig{
					Contexts:   []string{"prod", "staging"},
					Namespaces: []string{"default", "kube-system"},
				},
			},
			expectedContexts:   []string{"prod", "staging"},
			expectedNamespaces: []string{"default", "kube-system"},
		},
		{
			name: "contexts only",
			config: &config.Config{
				Kubernetes: &config.KubernetesConfig{
					Contexts: []string{"minikube"},
				},
			},
			expectedContexts:   []string{"minikube"},
			expectedNamespaces: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orch := NewOrchestrator(tt.config, "/tmp", false)
			contexts, namespaces := orch.getKubescapeConfig()
			assert.Equal(t, tt.expectedContexts, contexts)
			assert.Equal(t, tt.expectedNamespaces, namespaces)
		})
	}
}

func TestEnrichFindings(t *testing.T) {
	tests := []struct {
		config           *config.Config
		verifyEnrichment func(t *testing.T, enriched []models.EnrichedFinding)
		name             string
		findings         []models.Finding
		expectedEnriched int
	}{
		{
			name: "no metadata enrichment configured - returns empty",
			config: &config.Config{
				Client: config.ClientConfig{
					Name:        "test-client",
					Environment: "test",
				},
			},
			findings: []models.Finding{
				{
					ID:       "finding-1",
					Scanner:  "trivy",
					Type:     "vulnerability",
					Resource: "nginx:latest",
					Severity: "high",
					Title:    "CVE-2021-12345",
				},
			},
			expectedEnriched: 0,
		},
		{
			name: "empty metadata resources - returns empty",
			config: &config.Config{
				Client: config.ClientConfig{
					Name:        "test-client",
					Environment: "test",
				},
				MetadataEnrichment: config.MetadataEnrichment{
					Resources: map[string]config.ResourceMetadata{},
				},
			},
			findings: []models.Finding{
				{
					ID:       "finding-1",
					Scanner:  "trivy",
					Type:     "vulnerability",
					Resource: "nginx:latest",
					Severity: "high",
					Title:    "CVE-2021-12345",
				},
			},
			expectedEnriched: 0,
		},
		{
			name: "metadata enrichment with matching resources",
			config: &config.Config{
				Client: config.ClientConfig{
					Name:        "test-client",
					Environment: "test",
				},
				MetadataEnrichment: config.MetadataEnrichment{
					Resources: map[string]config.ResourceMetadata{
						"nginx:latest": {
							Owner:              "web-team",
							DataClassification: "public",
							BusinessImpact:     "Customer-facing web services",
							ComplianceImpact:   []string{"PCI-DSS", "SOC2"},
						},
						"postgres:14": {
							Owner:              "data-team",
							DataClassification: "confidential",
							BusinessImpact:     "Core customer database",
							ComplianceImpact:   []string{"GDPR", "HIPAA"},
						},
					},
				},
			},
			findings: []models.Finding{
				{
					ID:       "finding-1",
					Scanner:  "trivy",
					Type:     "vulnerability",
					Resource: "nginx:latest",
					Severity: "high",
					Title:    "CVE-2021-12345",
				},
				{
					ID:       "finding-2",
					Scanner:  "trivy",
					Type:     "vulnerability",
					Resource: "postgres:14",
					Severity: "critical",
					Title:    "CVE-2021-67890",
				},
				{
					ID:       "finding-3",
					Scanner:  "trivy",
					Type:     "vulnerability",
					Resource: "redis:7",
					Severity: "medium",
					Title:    "CVE-2021-11111",
				},
			},
			expectedEnriched: 3,
			verifyEnrichment: func(t *testing.T, enriched []models.EnrichedFinding) {
				// Check nginx enrichment
				nginx := enriched[0]
				assert.Equal(t, "nginx:latest", nginx.Resource)
				assert.Equal(t, "web-team", nginx.BusinessContext.Owner)
				assert.Equal(t, "public", nginx.BusinessContext.DataClassification)
				assert.Equal(t, "Customer-facing web services", nginx.BusinessContext.BusinessImpact)
				assert.ElementsMatch(t, []string{"PCI-DSS", "SOC2"}, nginx.BusinessContext.ComplianceImpact)

				// Check postgres enrichment
				postgres := enriched[1]
				assert.Equal(t, "postgres:14", postgres.Resource)
				assert.Equal(t, "data-team", postgres.BusinessContext.Owner)
				assert.Equal(t, "confidential", postgres.BusinessContext.DataClassification)
				assert.Equal(t, "Core customer database", postgres.BusinessContext.BusinessImpact)
				assert.ElementsMatch(t, []string{"GDPR", "HIPAA"}, postgres.BusinessContext.ComplianceImpact)

				// Check redis (no enrichment)
				redis := enriched[2]
				assert.Equal(t, "redis:7", redis.Resource)
				assert.Empty(t, redis.BusinessContext.Owner)
				assert.Empty(t, redis.BusinessContext.DataClassification)
			},
		},
		{
			name: "metadata enrichment with suppressed findings",
			config: &config.Config{
				Client: config.ClientConfig{
					Name:        "test-client",
					Environment: "test",
				},
				MetadataEnrichment: config.MetadataEnrichment{
					Resources: map[string]config.ResourceMetadata{
						"nginx:latest": {
							Owner:              "web-team",
							DataClassification: "public",
						},
					},
				},
			},
			findings: []models.Finding{
				{
					ID:         "finding-1",
					Scanner:    "trivy",
					Type:       "vulnerability",
					Resource:   "nginx:latest",
					Severity:   "high",
					Title:      "CVE-2021-12345",
					Suppressed: true,
				},
				{
					ID:       "finding-2",
					Scanner:  "trivy",
					Type:     "vulnerability",
					Resource: "nginx:latest",
					Severity: "medium",
					Title:    "CVE-2021-67890",
				},
			},
			expectedEnriched: 2,
			verifyEnrichment: func(t *testing.T, enriched []models.EnrichedFinding) {
				// Both findings should be enriched, regardless of suppression status
				for _, ef := range enriched {
					assert.Equal(t, "web-team", ef.BusinessContext.Owner)
					assert.Equal(t, "public", ef.BusinessContext.DataClassification)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orch := NewOrchestrator(tt.config, "/tmp", false)

			// Create scan metadata with findings
			metadata := &models.ScanMetadata{
				Results: map[string]*models.ScanResult{
					"test-scanner": {
						Scanner:  "test-scanner",
						Findings: tt.findings,
					},
				},
			}

			// Enrich findings
			enriched := orch.EnrichFindings(metadata)

			// Verify count
			assert.Len(t, enriched, tt.expectedEnriched)

			// Run custom verification if provided
			if tt.verifyEnrichment != nil && len(enriched) > 0 {
				tt.verifyEnrichment(t, enriched)
			}
		})
	}
}

func TestEnrichFindingsMultipleScanners(t *testing.T) {
	cfg := &config.Config{
		Client: config.ClientConfig{
			Name:        "test-client",
			Environment: "test",
		},
		MetadataEnrichment: config.MetadataEnrichment{
			Resources: map[string]config.ResourceMetadata{
				"s3://my-bucket": {
					Owner:              "storage-team",
					DataClassification: "sensitive",
					BusinessImpact:     "Customer data storage",
				},
				"nginx:latest": {
					Owner:              "web-team",
					DataClassification: "public",
				},
			},
		},
	}

	orch := NewOrchestrator(cfg, "/tmp", false)

	metadata := &models.ScanMetadata{
		Results: map[string]*models.ScanResult{
			"prowler": {
				Scanner: "prowler",
				Findings: []models.Finding{
					{
						ID:       "finding-1",
						Scanner:  "prowler",
						Type:     "s3-bucket-public",
						Resource: "s3://my-bucket",
						Severity: "high",
						Title:    "S3 bucket is public",
					},
				},
			},
			"trivy": {
				Scanner: "trivy",
				Findings: []models.Finding{
					{
						ID:       "finding-2",
						Scanner:  "trivy",
						Type:     "vulnerability",
						Resource: "nginx:latest",
						Severity: "medium",
						Title:    "CVE-2021-12345",
					},
				},
			},
			"gitleaks": {
				Scanner: "gitleaks",
				Findings: []models.Finding{
					{
						ID:       "finding-3",
						Scanner:  "gitleaks",
						Type:     "secret",
						Resource: "src/config.js",
						Severity: "critical",
						Title:    "AWS key exposed",
					},
				},
			},
		},
	}

	enriched := orch.EnrichFindings(metadata)

	// Should have all 3 findings enriched
	assert.Len(t, enriched, 3)

	// Verify enrichment by scanner
	prowlerFinding := findEnrichedByID(enriched, "finding-1")
	assert.NotNil(t, prowlerFinding)
	assert.Equal(t, "storage-team", prowlerFinding.BusinessContext.Owner)
	assert.Equal(t, "sensitive", prowlerFinding.BusinessContext.DataClassification)
	assert.Equal(t, "Customer data storage", prowlerFinding.BusinessContext.BusinessImpact)

	trivyFinding := findEnrichedByID(enriched, "finding-2")
	assert.NotNil(t, trivyFinding)
	assert.Equal(t, "web-team", trivyFinding.BusinessContext.Owner)
	assert.Equal(t, "public", trivyFinding.BusinessContext.DataClassification)

	gitleaksFinding := findEnrichedByID(enriched, "finding-3")
	assert.NotNil(t, gitleaksFinding)
	assert.Empty(t, gitleaksFinding.BusinessContext.Owner) // No metadata for this resource
}

// Helper function to find enriched finding by ID.
func findEnrichedByID(findings []models.EnrichedFinding, id string) *models.EnrichedFinding {
	for _, f := range findings {
		if f.ID == id {
			return &f
		}
	}
	return nil
}
