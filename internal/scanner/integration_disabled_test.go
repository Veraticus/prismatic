//go:build integration
// +build integration

package scanner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Veraticus/prismatic/internal/config"
	"github.com/Veraticus/prismatic/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDisabledScanners_Integration(t *testing.T) {
	// Create a test configuration with some scanners disabled
	testDir := t.TempDir()
	
	// Create test repo for gitleaks/checkov
	repoDir := filepath.Join(testDir, "test-repo")
	require.NoError(t, os.MkdirAll(repoDir, 0755))
	
	// Create a simple file
	testFile := filepath.Join(repoDir, "test.py")
	require.NoError(t, os.WriteFile(testFile, []byte("print('hello')"), 0600))

	cfg := &config.Config{
		Client: config.ClientConfig{
			Name:        "test-disabled",
			Environment: "test",
		},
		Repositories: []config.Repository{
			{
				Name:   "test-repo",
				Path:   repoDir,
				Branch: "main",
			},
		},
		Scanners: map[string]config.ScannerConfig{
			"gitleaks": {Enabled: false}, // Disable gitleaks
			"checkov":  {Enabled: true},  // Keep checkov enabled
		},
	}

	// Create orchestrator
	outputDir := filepath.Join(testDir, "output")
	orch := NewOrchestratorWithLogger(cfg, outputDir, false, logger.NewMockLogger())

	// Initialize scanners
	err := orch.InitializeScanners(nil)
	require.NoError(t, err)

	// Get scanner names
	scannerNames := orch.getScannerNames()
	
	// Verify gitleaks is NOT included
	assert.NotContains(t, scannerNames, "gitleaks")
	
	// Verify checkov IS included
	assert.Contains(t, scannerNames, "checkov")

	// Run scans
	ctx := context.Background()
	metadata, err := orch.RunScans(ctx)
	require.NoError(t, err)
	require.NotNil(t, metadata)

	// Verify results don't contain gitleaks
	_, hasGitleaks := metadata.Results["gitleaks"]
	assert.False(t, hasGitleaks, "gitleaks results should not be present")

	// Verify results do contain checkov (if available)
	_, hasCheckov := metadata.Results["checkov"]
	if isCommandAvailable("checkov") {
		assert.True(t, hasCheckov, "checkov results should be present")
	}
}

func TestDisabledScannersWithOnlyFlag_Integration(t *testing.T) {
	// Test that --only flag still respects disabled scanners
	testDir := t.TempDir()
	
	cfg := &config.Config{
		Client: config.ClientConfig{
			Name:        "test-only-disabled",
			Environment: "test",
		},
		Docker: &config.DockerConfig{
			Containers: []string{"alpine:3.18"},
		},
		Repositories: []config.Repository{
			{
				Name:   "test-repo",
				Path:   testDir,
				Branch: "main",
			},
		},
		Scanners: map[string]config.ScannerConfig{
			"trivy":    {Enabled: false}, // Disable trivy
			"gitleaks": {Enabled: false}, // Disable gitleaks
		},
	}

	// Create orchestrator
	outputDir := filepath.Join(testDir, "output")
	orch := NewOrchestratorWithLogger(cfg, outputDir, false, logger.NewMockLogger())

	// Try to initialize with --only flag that includes disabled scanners
	err := orch.InitializeScanners([]string{"trivy", "gitleaks", "checkov"})
	require.NoError(t, err)

	// Get scanner names
	scannerNames := orch.getScannerNames()
	
	// Verify disabled scanners are NOT included even when explicitly requested
	assert.NotContains(t, scannerNames, "trivy")
	assert.NotContains(t, scannerNames, "gitleaks")
	
	// Verify enabled scanner IS included
	assert.Contains(t, scannerNames, "checkov")
}

// isCommandAvailable checks if a command is available in PATH
func isCommandAvailable(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}