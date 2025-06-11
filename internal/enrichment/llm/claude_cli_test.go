package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/joshsymonds/prismatic/internal/enrichment"
	"github.com/joshsymonds/prismatic/internal/models"
)

// Helper to create a fake claude CLI for testing.
func createFakeClaude(t *testing.T, response string, exitCode int) (string, func()) {
	t.Helper()

	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "claude-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Create a fake claude script
	claudePath := tmpDir + "/claude"
	script := fmt.Sprintf(`#!/bin/bash
echo '%s'
exit %d
`, response, exitCode)

	if err := os.WriteFile(claudePath, []byte(script), 0755); err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to create fake claude: %v", err)
	}

	// Add to PATH
	oldPath := os.Getenv("PATH")
	_ = os.Setenv("PATH", tmpDir+":"+oldPath)

	cleanup := func() {
		_ = os.Setenv("PATH", oldPath)
		os.RemoveAll(tmpDir)
	}

	return claudePath, cleanup
}

func TestClaudeCLIDriver_GetCapabilities(t *testing.T) {
	driver := &ClaudeCLIDriver{}
	caps := driver.GetCapabilities()

	if caps.ModelName != "claude-3-sonnet" {
		t.Errorf("Expected model name 'claude-3-sonnet', got %s", caps.ModelName)
	}

	if caps.MaxTokensPerRequest != 200000 {
		t.Errorf("Expected max tokens per request 200000, got %d", caps.MaxTokensPerRequest)
	}

	if !caps.SupportsJSONMode {
		t.Error("Expected SupportsJSONMode to be true")
	}
}

func TestClaudeCLIDriver_EstimateTokens(t *testing.T) {
	driver := &ClaudeCLIDriver{}

	tests := []struct {
		prompt      string
		minExpected int
		maxExpected int
	}{
		{"Hello world", 2, 5},
		{"", 0, 0},
		{"This is a longer prompt with multiple words and sentences.", 10, 20},
		{string(make([]byte, 1000)), 200, 300}, // 1000 chars should be ~250 tokens
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("prompt length %d", len(tt.prompt)), func(t *testing.T) {
			tokens, err := driver.EstimateTokens(tt.prompt)
			if err != nil {
				t.Fatalf("EstimateTokens failed: %v", err)
			}

			if tokens < tt.minExpected || tokens > tt.maxExpected {
				t.Errorf("Expected tokens between %d and %d, got %d", tt.minExpected, tt.maxExpected, tokens)
			}
		})
	}
}

func TestClaudeCLIDriver_Configure(t *testing.T) {
	driver := &ClaudeCLIDriver{}

	tests := []struct {
		config  map[string]interface{}
		name    string
		wantErr bool
	}{
		{
			name: "Valid configuration",
			config: map[string]interface{}{
				"model":      "claude-3-opus",
				"max_tokens": 4096,
			},
			wantErr: false,
		},
		{
			name:    "Empty configuration",
			config:  map[string]interface{}{},
			wantErr: false,
		},
		{
			name: "Configuration with extra fields",
			config: map[string]interface{}{
				"model": "claude-3-sonnet",
				"extra": "ignored",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := driver.Configure(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("Configure() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr && tt.config["model"] != nil {
				modelStr, ok := tt.config["model"].(string)
				if ok && driver.model != modelStr {
					t.Errorf("Expected model to be %s, got %s", modelStr, driver.model)
				}
			}
		})
	}
}

func TestClaudeCLIDriver_HealthCheck(t *testing.T) {
	// Test with fake claude that succeeds
	successResponse := "Claude CLI version 1.0.0"
	_, cleanup := createFakeClaude(t, successResponse, 0)
	defer cleanup()

	driver := &ClaudeCLIDriver{}
	ctx := context.Background()

	err := driver.HealthCheck(ctx)
	if err != nil {
		t.Errorf("HealthCheck failed: %v", err)
	}
}

func TestClaudeCLIDriver_HealthCheck_Failure(t *testing.T) {
	// Test with fake claude that fails
	_, cleanup := createFakeClaude(t, "Error", 1)
	defer cleanup()

	driver := &ClaudeCLIDriver{}
	ctx := context.Background()

	err := driver.HealthCheck(ctx)
	if err == nil {
		t.Error("Expected HealthCheck to fail")
	}
}

func TestClaudeCLIDriver_Enrich(t *testing.T) {
	findings := []models.Finding{
		{
			ID:       "test-1",
			Severity: "high",
			Title:    "Test Finding",
			Type:     "security/vulnerability",
		},
	}

	expectedEnrichments := []enrichment.FindingEnrichment{
		{
			FindingID: "test-1",
			Analysis: enrichment.Analysis{
				BusinessImpact:    "High impact on production",
				PriorityReasoning: "Critical vulnerability",
				TechnicalDetails:  "Security issue found",
				PriorityScore:     0.9,
			},
			Remediation: enrichment.Remediation{
				Immediate:       []string{"Apply patch"},
				ShortTerm:       []string{"Update dependencies"},
				EstimatedEffort: "1 hour",
			},
		},
	}

	response, _ := json.Marshal(expectedEnrichments)
	_, cleanup := createFakeClaude(t, string(response), 0)
	defer cleanup()

	driver := &ClaudeCLIDriver{}
	ctx := context.Background()

	enrichments, err := driver.Enrich(ctx, findings, "test prompt")
	if err != nil {
		t.Fatalf("Enrich failed: %v", err)
	}

	if len(enrichments) != 1 {
		t.Errorf("Expected 1 enrichment, got %d", len(enrichments))
	}

	if enrichments[0].FindingID != "test-1" {
		t.Errorf("Expected finding ID 'test-1', got %s", enrichments[0].FindingID)
	}
}

func TestClaudeCLIDriver_Enrich_InvalidJSON(t *testing.T) {
	findings := []models.Finding{
		{
			ID:       "test-1",
			Severity: "high",
			Title:    "Test Finding",
		},
	}

	// Invalid JSON response
	_, cleanup := createFakeClaude(t, "invalid json", 0)
	defer cleanup()

	driver := &ClaudeCLIDriver{}
	ctx := context.Background()

	_, err := driver.Enrich(ctx, findings, "test prompt")
	if err == nil {
		t.Error("Expected Enrich to fail with invalid JSON")
	}
}

func TestClaudeCLIDriver_Enrich_EmptyResponse(t *testing.T) {
	findings := []models.Finding{
		{
			ID:       "test-1",
			Severity: "high",
			Title:    "Test Finding",
		},
	}

	// Empty array response
	_, cleanup := createFakeClaude(t, "[]", 0)
	defer cleanup()

	driver := &ClaudeCLIDriver{}
	ctx := context.Background()

	enrichments, err := driver.Enrich(ctx, findings, "test prompt")
	if err != nil {
		t.Fatalf("Enrich failed: %v", err)
	}

	if len(enrichments) != 0 {
		t.Errorf("Expected 0 enrichments, got %d", len(enrichments))
	}
}

func TestClaudeCLIDriver_CommandNotFound(t *testing.T) {
	// Remove claude from PATH
	oldPath := os.Getenv("PATH")
	_ = os.Setenv("PATH", "/nonexistent")
	defer os.Setenv("PATH", oldPath)

	driver := &ClaudeCLIDriver{}
	ctx := context.Background()

	err := driver.HealthCheck(ctx)
	if err == nil {
		t.Error("Expected HealthCheck to fail when claude is not in PATH")
	}

	// Check if it's the right type of error
	if _, ok := err.(*exec.Error); !ok {
		t.Errorf("Expected exec.Error, got %T", err)
	}
}
