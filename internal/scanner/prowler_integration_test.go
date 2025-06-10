//go:build integration
// +build integration

package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Veraticus/prismatic/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProwlerScanner_TestDataIntegration tests Prowler using pre-generated test data
func TestProwlerScanner_TestDataIntegration(t *testing.T) {
	// This test uses pre-generated Prowler output to test the scanner
	// without requiring AWS credentials
	testDataDir := filepath.Join("..", "..", "testdata", "scanner", "prowler")

	t.Run("Parse Pre-Generated OCSF Output", func(t *testing.T) {
		// Check if test data exists
		ocsfFile := filepath.Join(testDataDir, "ocsf-output.json")
		if _, err := os.Stat(ocsfFile); os.IsNotExist(err) {
			t.Skip("Test data not found. Run: ./scripts/test/generate-prowler-testdata.sh")
		}

		data, err := os.ReadFile(ocsfFile)
		require.NoError(t, err)

		scanner := NewProwlerScanner(Config{}, []string{"test"}, []string{"us-east-1"}, nil)
		findings, err := scanner.ParseResults(data)
		require.NoError(t, err)

		// Verify findings
		assert.NotEmpty(t, findings)
		for _, finding := range findings {
			assert.Equal(t, "prowler", finding.Scanner)
			assert.NotEmpty(t, finding.ID)
			assert.NotEmpty(t, finding.Title)
			assert.NotEmpty(t, finding.Severity)
			assert.NotEmpty(t, finding.Type)
		}
	})

	t.Run("Parse Pre-Generated Native Output", func(t *testing.T) {
		nativeFile := filepath.Join(testDataDir, "native-output.json")
		if _, err := os.Stat(nativeFile); os.IsNotExist(err) {
			t.Skip("Test data not found. Run: ./scripts/test/generate-prowler-testdata.sh")
		}

		data, err := os.ReadFile(nativeFile)
		require.NoError(t, err)

		scanner := NewProwlerScanner(Config{}, []string{"test"}, []string{"us-east-1"}, nil)
		findings, err := scanner.ParseResults(data)
		require.NoError(t, err)

		// Verify findings structure
		for _, finding := range findings {
			assert.NotEmpty(t, finding.Resource)
			assert.NotEmpty(t, finding.Location)
			assert.NotEmpty(t, finding.Description)

			// Check metadata
			assert.NotEmpty(t, finding.Metadata["check_id"])
			if region, ok := finding.Metadata["region"]; ok {
				assert.NotEmpty(t, region)
			}
		}
	})
}

// TestProwlerScanner_RealAWSIntegration tests Prowler with real AWS credentials
// This test is skipped in CI and only runs when AWS credentials are available
func TestProwlerScanner_RealAWSIntegration(t *testing.T) {
	// Skip if prowler is not installed
	if _, err := exec.LookPath("prowler"); err != nil {
		t.Skip("prowler not installed")
	}

	// Skip if no AWS credentials
	if os.Getenv("AWS_ACCESS_KEY_ID") == "" && os.Getenv("AWS_PROFILE") == "" {
		t.Skip("AWS credentials not available")
	}

	// Skip if running in CI without explicit permission
	if os.Getenv("CI") == "true" && os.Getenv("ENABLE_AWS_TESTS") != "true" {
		t.Skip("AWS tests disabled in CI")
	}

	t.Run("Limited IAM Scan", func(t *testing.T) {
		// Use a very limited scan to minimize AWS API calls
		cfg := Config{
			WorkingDir: t.TempDir(),
			Timeout:    60, // Short timeout
			Debug:      true,
		}

		// Only scan specific low-impact checks
		scanner := NewProwlerScannerWithLogger(
			cfg,
			[]string{"default"},   // Use default profile
			[]string{"us-east-1"}, // Single region
			[]string{"iam"},       // Only IAM service
			logger.GetGlobalLogger(),
		)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		result, err := scanner.Scan(ctx)

		// Prowler might return ErrNoTargets if no issues found
		if err == ErrNoTargets {
			t.Log("No findings found (this is OK)")
			return
		}

		require.NoError(t, err)
		assert.NotNil(t, result)

		// Log what we found
		t.Logf("Prowler scan completed: %d findings", len(result.Findings))

		// If we have findings, validate their structure
		if len(result.Findings) > 0 {
			finding := result.Findings[0]
			assert.Equal(t, "prowler", finding.Scanner)
			assert.NotEmpty(t, finding.Title)
			assert.NotEmpty(t, finding.Severity)
			assert.Contains(t, []string{"low", "medium", "high", "critical"}, finding.Severity)

			// Log a sample finding
			t.Logf("Sample finding: %s (severity: %s)", finding.Title, finding.Severity)
		}
	})
}

// TestProwlerScanner_MockExecution tests the scanner with a mocked Prowler binary
func TestProwlerScanner_MockExecution(t *testing.T) {
	// Create a temporary directory for our mock
	mockDir := t.TempDir()
	mockProwler := filepath.Join(mockDir, "prowler")

	// Create a mock prowler script
	mockScript := `#!/bin/bash
# Mock prowler script for testing
echo '[{
	"metadata": {
		"event_code": "test_check_failed",
		"product": {"name": "Prowler", "version": "4.0.0"}
	},
	"severity": "High",
	"status": "FAIL",
	"status_detail": "Test finding for mock execution",
	"resources": [{
		"uid": "arn:aws:test::123456789012:resource/test",
		"type": "test_resource",
		"region": "us-east-1"
	}],
	"finding": {
		"type": "test-misconfiguration",
		"title": "Test Check Failed",
		"desc": "This is a test finding from mock execution",
		"remediation": {
			"desc": "Fix the test issue",
			"references": ["https://example.com/fix"]
		}
	}
}]' > prowler-output/output/output.ocsf.json
mkdir -p prowler-output/output
exit 3  # Prowler returns 3 when findings exist
`

	err := os.WriteFile(mockProwler, []byte(mockScript), 0755)
	require.NoError(t, err)

	// Override PATH to use our mock
	oldPath := os.Getenv("PATH")
	defer os.Setenv("PATH", oldPath)
	os.Setenv("PATH", mockDir+":"+oldPath)

	// Test the scanner
	cfg := Config{
		WorkingDir: t.TempDir(),
		Timeout:    10,
	}

	scanner := NewProwlerScanner(cfg, []string{"mock-profile"}, []string{"us-east-1"}, nil)

	ctx := context.Background()
	result, err := scanner.Scan(ctx)
	require.NoError(t, err)
	assert.NotNil(t, result)

	// Should have one finding from our mock
	require.Len(t, result.Findings, 1)

	finding := result.Findings[0]
	assert.Equal(t, "prowler", finding.Scanner)
	assert.Equal(t, "test-misconfiguration", finding.Type)
	assert.Equal(t, "high", finding.Severity)
	assert.Equal(t, "Test Check Failed", finding.Title)
	assert.Contains(t, finding.Description, "test finding from mock execution")
}

// TestProwlerScanner_ErrorHandling tests error scenarios
func TestProwlerScanner_ErrorHandling(t *testing.T) {
	t.Run("No Profiles Configured", func(t *testing.T) {
		scanner := NewProwlerScanner(Config{}, []string{}, nil, nil)
		result, err := scanner.Scan(context.Background())
		assert.ErrorIs(t, err, ErrNoTargets)
		assert.NotNil(t, result)
		assert.Empty(t, result.Findings)
	})

	t.Run("Context Cancellation", func(t *testing.T) {
		// Create a scanner that would take time to run
		scanner := NewProwlerScanner(
			Config{Timeout: 300},
			[]string{"profile1", "profile2", "profile3"},
			[]string{"all"},
			nil,
		)

		// Cancel context immediately
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		result, err := scanner.Scan(ctx)
		assert.NoError(t, err) // Prowler scanner returns nil error but sets Error field
		assert.NotNil(t, result)
		assert.Contains(t, result.Error, "canceled")
	})

	t.Run("Invalid JSON Parsing", func(t *testing.T) {
		scanner := NewProwlerScanner(Config{}, []string{"test"}, nil, nil)

		testCases := []struct {
			name  string
			input string
		}{
			{"Empty", ""},
			{"Invalid JSON", "{invalid json}"},
			{"Wrong Format", `{"wrong": "format"}`},
			{"HTML Error", "<html>Error page</html>"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := scanner.ParseResults([]byte(tc.input))
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "prowler:")
			})
		}
	})
}

// TestProwlerScanner_OutputFormats tests parsing different Prowler output formats
func TestProwlerScanner_OutputFormats(t *testing.T) {
	scanner := NewProwlerScanner(Config{}, []string{"test"}, nil, nil)

	t.Run("OCSF Format Array", func(t *testing.T) {
		input := `[
			{
				"metadata": {"event_code": "check1"},
				"status": "FAIL",
				"severity": "High",
				"resources": [{"uid": "arn:aws:s3:::bucket1", "region": "us-east-1"}],
				"finding": {"type": "misconfiguration", "title": "Check 1 Failed"}
			},
			{
				"metadata": {"event_code": "check2"},
				"status": "PASS"
			}
		]`

		findings, err := scanner.ParseResults([]byte(input))
		require.NoError(t, err)
		assert.Len(t, findings, 1) // Only FAIL status
		assert.Equal(t, "check1", findings[0].Metadata["check_id"])
	})

	t.Run("OCSF Format NDJSON", func(t *testing.T) {
		input := `{"metadata":{"event_code":"check1"},"status":"FAIL","severity":"Medium","resources":[{"uid":"res1"}],"finding":{"type":"iam","title":"Title1"}}
{"metadata":{"event_code":"check2"},"status":"FAIL","severity":"Low","resources":[{"uid":"res2"}],"finding":{"type":"encryption","title":"Title2"}}
{"metadata":{"event_code":"check3"},"status":"PASS"}`

		findings, err := scanner.ParseResults([]byte(input))
		require.NoError(t, err)
		assert.Len(t, findings, 2) // Two FAIL statuses
	})

	t.Run("Native Format Array", func(t *testing.T) {
		input := `[
			{
				"Status": "FAIL",
				"CheckID": "s3_bucket_public_access",
				"Severity": "critical",
				"ResourceArn": "arn:aws:s3:::my-bucket",
				"Region": "us-west-2",
				"CheckTitle": "S3 Bucket Public Access",
				"Description": "Bucket allows public access"
			}
		]`

		findings, err := scanner.ParseResults([]byte(input))
		require.NoError(t, err)
		assert.Len(t, findings, 1)
		assert.Equal(t, "internet-exposed", findings[0].Type)
	})

	t.Run("Mixed Format Fallback", func(t *testing.T) {
		// Start with native format that looks like it might be OCSF
		input := `[
			{
				"metadata": "not-ocsf-structure",
				"Status": "FAIL",
				"CheckID": "test_check",
				"Severity": "high",
				"ResourceId": "test-resource"
			}
		]`

		findings, err := scanner.ParseResults([]byte(input))
		require.NoError(t, err)
		// Should fall back to native format parser
		assert.Len(t, findings, 1)
	})
}

// TestProwlerScanner_LargeOutput tests handling of large result sets
func TestProwlerScanner_LargeOutput(t *testing.T) {
	scanner := NewProwlerScanner(Config{}, []string{"test"}, nil, nil)

	// Generate large NDJSON output
	var largeOutput string
	for i := 0; i < 1000; i++ {
		if i > 0 {
			largeOutput += "\n"
		}
		largeOutput += fmt.Sprintf(`{"metadata":{"event_code":"check_%d"},"status":"FAIL","severity":"Medium","resources":[{"uid":"resource-%d"}],"finding":{"type":"misconfiguration","title":"Finding %d"}}`, i, i, i)
	}

	start := time.Now()
	findings, err := scanner.ParseResults([]byte(largeOutput))
	duration := time.Since(start)

	require.NoError(t, err)
	assert.Len(t, findings, 1000)
	assert.Less(t, duration, 5*time.Second, "Parsing should be fast")

	// Verify each finding has unique ID
	ids := make(map[string]bool)
	for _, f := range findings {
		assert.False(t, ids[f.ID], "Duplicate ID found: %s", f.ID)
		ids[f.ID] = true
	}
}

// Helper function to generate test Prowler output
func generateMockProwlerOutput(checkCount int, format string) []byte {
	if format == "ocsf" {
		var checks []ProwlerOCSFCheck
		for i := 0; i < checkCount; i++ {
			checks = append(checks, ProwlerOCSFCheck{
				Status:   "FAIL",
				Severity: "Medium",
				// ... populate other fields
			})
		}
		data, _ := json.Marshal(checks)
		return data
	}

	// Native format
	var checks []ProwlerNativeCheck
	for i := 0; i < checkCount; i++ {
		checks = append(checks, ProwlerNativeCheck{
			Status:   "FAIL",
			Severity: "medium",
			CheckID:  fmt.Sprintf("check_%d", i),
			// ... populate other fields
		})
	}
	data, _ := json.Marshal(checks)
	return data
}
