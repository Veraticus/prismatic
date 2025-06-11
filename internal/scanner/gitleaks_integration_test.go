//go:build integration
// +build integration

package scanner

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/joshsymonds/prismatic/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitleaksScanner_Integration(t *testing.T) {
	// Skip if gitleaks is not installed
	if _, err := exec.LookPath("gitleaks"); err != nil {
		t.Skip("gitleaks not installed")
	}

	// Create a temporary directory with git repo
	tempDir := t.TempDir()

	// Initialize git repo
	cmd := exec.Command("git", "init")
	cmd.Dir = tempDir
	require.NoError(t, cmd.Run())

	// Configure git user for commits
	cmd = exec.Command("git", "config", "user.email", "test@example.com")
	cmd.Dir = tempDir
	require.NoError(t, cmd.Run())

	cmd = exec.Command("git", "config", "user.name", "Test User")
	cmd.Dir = tempDir
	require.NoError(t, cmd.Run())

	// Create a file with secrets that gitleaks will actually detect
	secretsFile := filepath.Join(tempDir, "secrets.py")
	secretsContent := `# Test secrets that should be detected
# Real-looking AWS access key (not the example one)
aws_access_key_id = "AKIA_FAKE_TEST_J7Q2VKXYKDT5WHFQ"
aws_secret_access_key = "FAKE_TEST_bPxRfiCYEXAMPLEKEY+wJalrXUtnFEMI/K7MDENG"

# GitHub token
github_token = "ghp_FAKE_TEST_16C7e42F292c6912E7710c838347Ae178B4a"

# Slack token
slack_token = "xoxb-FAKE-263594206564-2343594206564-WRjgnr4fNkfnvar4WV5cMFmo"

# Private key
private_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA04up8hoqzS1+APIB0RhjXyObwHQnOzhAk5Bd7mhkSbPkyhP1
-----END RSA PRIVATE KEY-----"""

# Generic API key
api_key = "sk-1234567890abcdef1234567890abcdef"
`
	require.NoError(t, os.WriteFile(secretsFile, []byte(secretsContent), 0644))

	// Add and commit
	cmd = exec.Command("git", "add", ".")
	cmd.Dir = tempDir
	require.NoError(t, cmd.Run())

	cmd = exec.Command("git", "commit", "-m", "test secrets")
	cmd.Dir = tempDir
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "git commit failed: %s", string(output))

	// First, run gitleaks directly to see what it produces
	reportPath := filepath.Join(tempDir, "gitleaks-report.json")
	cmd = exec.Command("gitleaks", "git", ".", "--report-path", reportPath, "--exit-code", "0")
	cmd.Dir = tempDir
	output, err = cmd.CombinedOutput()
	t.Logf("Gitleaks direct output: %s", string(output))
	require.NoError(t, err, "gitleaks command failed: %s", string(output))

	// Read the actual JSON output
	reportData, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	t.Logf("Gitleaks JSON output sample: %.500s", string(reportData))

	// Parse it to verify structure
	var leaks []GitleaksLeak
	require.NoError(t, json.Unmarshal(reportData, &leaks))
	require.NotEmpty(t, leaks, "Gitleaks should have found secrets")

	// Now test our scanner
	cfg := Config{
		WorkingDir: tempDir,
		Timeout:    300,
	}

	// Create scanner with repositories map for the new API
	repositories := map[string]string{
		"test-repo": tempDir,
	}
	scanner := NewGitleaksScannerWithRepositories(cfg, repositories, logger.GetGlobalLogger())

	// Run scan
	ctx := context.Background()
	result, err := scanner.Scan(ctx)
	require.NoError(t, err)
	assert.NotNil(t, result)

	// Debug: log the raw output
	if result.Error != "" {
		t.Logf("Scanner error: %s", result.Error)
	}

	// Debug: Try running gitleaks through our scanner's runGitleaks method
	testScanner := &GitleaksScanner{
		BaseScanner: scanner.BaseScanner,
		targetPath:  tempDir,
		repoPaths:   nil,
	}
	testOutput, testErr := testScanner.runGitleaks(ctx)
	t.Logf("Direct runGitleaks test - output len: %d, err: %v", len(testOutput), testErr)
	if len(testOutput) > 0 {
		t.Logf("Direct runGitleaks output sample: %.200s", string(testOutput))

		// Try parsing the output
		parsedFindings, parseErr := scanner.ParseResults(testOutput)
		t.Logf("Parsed %d findings from direct output, err: %v", len(parsedFindings), parseErr)
	}

	// Log scanner result details
	t.Logf("Scanner result - findings: %d, error: %s", len(result.Findings), result.Error)

	// Should find the same number of secrets as direct gitleaks
	assert.Equal(t, len(leaks), len(result.Findings), "Scanner should find same number of secrets as direct gitleaks")

	// Check findings match what gitleaks found
	foundRules := make(map[string]bool)
	for _, finding := range result.Findings {
		assert.Equal(t, "gitleaks", finding.Scanner)
		assert.Equal(t, "secret", finding.Type)
		assert.Equal(t, "critical", finding.Severity)
		assert.NotEmpty(t, finding.Title)
		assert.NotEmpty(t, finding.Description)
		assert.NotEmpty(t, finding.Metadata["rule_id"])
		assert.NotEmpty(t, finding.Metadata["commit"])
		// Check for either secret or match_pattern (redacted secret)
		if finding.Metadata["secret"] == "" {
			assert.NotEmpty(t, finding.Metadata["match_pattern"])
		}
		assert.Contains(t, finding.Description, "line")

		// Track which rules we found
		if ruleID, ok := finding.Metadata["rule_id"]; ok {
			foundRules[ruleID] = true
			t.Logf("Found rule: %s", ruleID)
		}
	}

	// Log what rules were found for debugging
	t.Logf("Found rules: %v", foundRules)

	// Verify we found at least some expected secret types
	expectedAny := []string{
		"aws-access-token", "aws-access-key", // AWS
		"github-pat", "github-personal-access-token", // GitHub
		"private-key", "asymmetric-private-key", // Private key
		"slack-bot-token", "slack-user-token", // Slack
		"generic-api-key", // Generic
	}

	foundExpected := false
	for _, expected := range expectedAny {
		if foundRules[expected] {
			foundExpected = true
			break
		}
	}
	assert.True(t, foundExpected, "Should find at least one expected secret type from: %v", expectedAny)
}
