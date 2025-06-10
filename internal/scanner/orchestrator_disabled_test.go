package scanner

import (
	"testing"

	"github.com/Veraticus/prismatic/internal/config"
	"github.com/Veraticus/prismatic/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOrchestrator_FilterEnabledScanners(t *testing.T) {
	tests := []struct {
		name           string
		scanners       []string
		scannerConfig  map[string]config.ScannerConfig
		expectedResult []string
	}{
		{
			name:           "No scanner config - all enabled by default",
			scanners:       []string{"prowler", "trivy", "nuclei"},
			scannerConfig:  nil,
			expectedResult: []string{"prowler", "trivy", "nuclei"},
		},
		{
			name:     "Some scanners disabled",
			scanners: []string{"prowler", "trivy", "nuclei", "kubescape"},
			scannerConfig: map[string]config.ScannerConfig{
				"trivy":     {Enabled: false},
				"kubescape": {Enabled: false},
			},
			expectedResult: []string{"prowler", "nuclei"},
		},
		{
			name:     "All scanners explicitly enabled",
			scanners: []string{"prowler", "trivy"},
			scannerConfig: map[string]config.ScannerConfig{
				"prowler": {Enabled: true},
				"trivy":   {Enabled: true},
			},
			expectedResult: []string{"prowler", "trivy"},
		},
		{
			name:     "Mix of explicit and implicit",
			scanners: []string{"prowler", "trivy", "nuclei"},
			scannerConfig: map[string]config.ScannerConfig{
				"trivy": {Enabled: false},
				// prowler and nuclei have no config, so enabled by default
			},
			expectedResult: []string{"prowler", "nuclei"},
		},
		{
			name:     "All scanners disabled",
			scanners: []string{"prowler", "trivy"},
			scannerConfig: map[string]config.ScannerConfig{
				"prowler": {Enabled: false},
				"trivy":   {Enabled: false},
			},
			expectedResult: []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{
				Client: config.ClientConfig{
					Name:        "test",
					Environment: "test",
				},
				Scanners: tc.scannerConfig,
			}

			orch := NewOrchestratorWithLogger(cfg, "/tmp", false, logger.NewMockLogger())
			result := orch.filterEnabledScanners(tc.scanners)
			assert.Equal(t, tc.expectedResult, result)
		})
	}
}

func TestOrchestrator_DetectScannersWithDisabled(t *testing.T) {
	t.Run("Disabled scanners not initialized", func(t *testing.T) {
		cfg := &config.Config{
			Client: config.ClientConfig{
				Name:        "test",
				Environment: "test",
			},
			AWS: &config.AWSConfig{
				Profiles: []string{"default"},
			},
			Docker: &config.DockerConfig{
				Containers: []string{"nginx:latest"},
			},
			Scanners: map[string]config.ScannerConfig{
				"prowler": {Enabled: false}, // Disable AWS scanning
				"trivy":   {Enabled: true},  // Keep Docker scanning
			},
		}

		orch := NewOrchestratorWithLogger(cfg, "/tmp", false, logger.NewMockLogger())
		scanners := orch.detectScanners(nil)

		// Should have trivy, gitleaks, checkov but NOT prowler
		assert.Contains(t, scanners, "trivy")
		assert.Contains(t, scanners, "gitleaks")
		assert.Contains(t, scanners, "checkov")
		assert.NotContains(t, scanners, "prowler")
	})

	t.Run("Only scanners filter still respects disabled", func(t *testing.T) {
		cfg := &config.Config{
			Client: config.ClientConfig{
				Name:        "test",
				Environment: "test",
			},
			Scanners: map[string]config.ScannerConfig{
				"trivy": {Enabled: false},
			},
		}

		orch := NewOrchestratorWithLogger(cfg, "/tmp", false, logger.NewMockLogger())

		// Request specific scanners
		requestedScanners := []string{"prowler", "trivy", "nuclei"}
		scanners := orch.detectScanners(requestedScanners)

		// Should have prowler and nuclei but NOT trivy
		assert.Contains(t, scanners, "prowler")
		assert.Contains(t, scanners, "nuclei")
		assert.NotContains(t, scanners, "trivy")
	})
}

func TestOrchestrator_InitializeScannersSkipsDisabled(t *testing.T) {
	cfg := &config.Config{
		Client: config.ClientConfig{
			Name:        "test",
			Environment: "test",
		},
		AWS: &config.AWSConfig{
			Profiles: []string{"default"},
		},
		Docker: &config.DockerConfig{
			Containers: []string{"nginx:latest"},
		},
		Repositories: []config.Repository{
			{
				Name:   "test-repo",
				Path:   "/tmp/test-repo",
				Branch: "main",
			},
		},
		Scanners: map[string]config.ScannerConfig{
			"prowler":  {Enabled: false},
			"gitleaks": {Enabled: false},
		},
	}

	orch := NewOrchestratorWithLogger(cfg, "/tmp", true, logger.NewMockLogger()) // Use mock
	err := orch.InitializeScanners(nil)
	require.NoError(t, err)

	// Get scanner names
	scannerNames := orch.getScannerNames()

	// Should have trivy and checkov but NOT prowler or gitleaks
	assert.Contains(t, scannerNames, "mock-trivy")
	assert.Contains(t, scannerNames, "mock-checkov")
	assert.NotContains(t, scannerNames, "mock-prowler")
	assert.NotContains(t, scannerNames, "mock-gitleaks")
}
