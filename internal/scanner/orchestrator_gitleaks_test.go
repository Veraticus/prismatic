package scanner

import (
	"context"
	"testing"

	"github.com/Veraticus/prismatic/internal/config"
	"github.com/Veraticus/prismatic/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOrchestratorGitleaksInScanners verifies that gitleaks appears in metadata.Scanners.
func TestOrchestratorGitleaksInScanners(t *testing.T) {
	// Create a test configuration
	cfg := &config.Config{
		Client: config.ClientConfig{
			Name:        "test-client",
			Environment: "test",
		},
		Repositories: []config.Repository{
			{
				Name: "test-repo",
				Path: "https://github.com/test/repo",
			},
		},
	}

	// Create orchestrator in mock mode
	testLogger := logger.NewMockLogger()
	orchestrator := NewOrchestratorWithLogger(cfg, t.TempDir(), true, testLogger)

	// Initialize scanners (gitleaks should be included by default)
	err := orchestrator.InitializeScanners(nil)
	require.NoError(t, err)

	// Get scanner names
	scannerNames := orchestrator.getScannerNames()
	t.Logf("Initialized scanners: %v", scannerNames)

	// In mock mode, gitleaks should be "mock-gitleaks"
	assert.Contains(t, scannerNames, "mock-gitleaks", "mock-gitleaks should be in scanner list")

	// Run scans
	ctx := context.Background()
	metadata, err := orchestrator.RunScans(ctx)
	require.NoError(t, err)

	// Check metadata.Scanners
	t.Logf("metadata.Scanners: %v", metadata.Scanners)
	assert.Contains(t, metadata.Scanners, "mock-gitleaks", "mock-gitleaks should be in metadata.Scanners")

	// Check if results exist for mock-gitleaks
	if result, ok := metadata.Results["mock-gitleaks"]; ok {
		t.Logf("mock-gitleaks result: Scanner=%s, Findings=%d, Error=%s",
			result.Scanner, len(result.Findings), result.Error)
	} else {
		t.Error("mock-gitleaks results not found in metadata.Results")
	}
}

// TestOrchestratorGitleaksRealMode tests gitleaks in non-mock mode.
func TestOrchestratorGitleaksRealMode(t *testing.T) {
	// Create a test configuration
	cfg := &config.Config{
		Client: config.ClientConfig{
			Name:        "test-client",
			Environment: "test",
		},
	}

	// Create orchestrator in real mode (not mock)
	testLogger := logger.NewMockLogger()
	orchestrator := NewOrchestratorWithLogger(cfg, t.TempDir(), false, testLogger)

	// Initialize scanners
	err := orchestrator.InitializeScanners(nil)
	require.NoError(t, err)

	// Get scanner names
	scannerNames := orchestrator.getScannerNames()
	t.Logf("Initialized scanners (real mode): %v", scannerNames)

	// In real mode, it should be just "gitleaks"
	assert.Contains(t, scannerNames, "gitleaks", "gitleaks should be in scanner list")
}
