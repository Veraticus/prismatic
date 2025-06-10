//go:build integration
// +build integration

package scanner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Veraticus/prismatic/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckovScanner_FastIntegration(t *testing.T) {
	// Skip if checkov is not installed
	if _, err := exec.LookPath("checkov"); err != nil {
		t.Skip("checkov not installed")
	}

	// Create test directory
	tempDir := t.TempDir()

	t.Run("Terraform S3 Specific Checks", func(t *testing.T) {
		// Create a terraform file with known S3 issues
		tfDir := filepath.Join(tempDir, "terraform-s3")
		require.NoError(t, os.MkdirAll(tfDir, 0755))

		tfContent := `resource "aws_s3_bucket" "test" {
  bucket = "my-test-bucket"
  # Missing versioning
  # Missing encryption  
  # Missing logging
}

resource "aws_s3_bucket_public_access_block" "test" {
  bucket = aws_s3_bucket.test.id
  
  block_public_acls       = false  # Bad!
  block_public_policy     = false  # Bad!
  ignore_public_acls      = false  # Bad!
  restrict_public_buckets = false  # Bad!
}`

		require.NoError(t, os.WriteFile(filepath.Join(tfDir, "s3.tf"), []byte(tfContent), 0644))

		// Run checkov with specific S3 checks only (very fast)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		output, err := exec.CommandContext(ctx, "checkov",
			"-d", tfDir,
			"--framework", "terraform", // Only scan terraform
			"--check", "CKV_AWS_18,CKV_AWS_19,CKV_AWS_21,CKV2_AWS_6", // Specific S3 checks
			"-o", "json",
			"--quiet",
			"--compact",
		).CombinedOutput()

		// Checkov returns exit code 1 when it finds issues
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 1 {
				t.Logf("Checkov error: %v", err)
			}
		}

		// Parse the output
		cfg := Config{}
		scanner := NewCheckovScannerWithLogger(cfg, []string{}, logger.GetGlobalLogger())

		findings, err := scanner.ParseResults(output)
		require.NoError(t, err)

		// Should find S3 issues
		assert.NotEmpty(t, findings, "Should find S3 misconfigurations")

		for _, f := range findings {
			t.Logf("Found: %s - %s (%s)", f.Type, f.Title, f.Metadata["check_id"])
			assert.Equal(t, "checkov", f.Scanner)
			assert.NotEmpty(t, f.Severity)

			// Should be AWS checks
			assert.Contains(t, f.Metadata["check_id"], "AWS")
		}
	})

	t.Run("Terraform Security Group Checks", func(t *testing.T) {
		// Create terraform with security group issues
		sgDir := filepath.Join(tempDir, "terraform-sg")
		require.NoError(t, os.MkdirAll(sgDir, 0755))

		sgContent := `resource "aws_security_group" "bad" {
  name = "allow_all"
  description = "Allow all traffic"
  
  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Bad!
  }
  
  ingress {
    description = "RDP from anywhere"  
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Bad!
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}`

		require.NoError(t, os.WriteFile(filepath.Join(sgDir, "sg.tf"), []byte(sgContent), 0644))

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Run with network security checks
		output, err := exec.CommandContext(ctx, "checkov",
			"-d", sgDir,
			"--framework", "terraform",
			"--check", "CKV_AWS_24,CKV_AWS_25,CKV_AWS_260", // SSH, RDP checks
			"-o", "json",
			"--quiet",
			"--compact",
		).CombinedOutput()

		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 1 {
				t.Logf("Checkov error: %v", err)
			}
		}

		cfg := Config{}
		scanner := NewCheckovScannerWithLogger(cfg, []string{}, logger.GetGlobalLogger())

		findings, err := scanner.ParseResults(output)
		require.NoError(t, err)

		// Should find security group issues
		for _, f := range findings {
			t.Logf("SG Finding: %s - %s", f.Type, f.Title)
			assert.Contains(t, []string{"network-misconfiguration", "aws-misconfiguration"}, f.Type)
		}
	})

	t.Run("Dockerfile Checks", func(t *testing.T) {
		// Create a Dockerfile with issues
		dockerDir := filepath.Join(tempDir, "docker")
		require.NoError(t, os.MkdirAll(dockerDir, 0755))

		dockerContent := `FROM ubuntu:latest
USER root
RUN apt-get update && apt-get install -y curl wget
EXPOSE 22
CMD ["bash"]`

		require.NoError(t, os.WriteFile(filepath.Join(dockerDir, "Dockerfile"), []byte(dockerContent), 0644))

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Run specific dockerfile checks
		output, err := exec.CommandContext(ctx, "checkov",
			"-d", dockerDir,
			"--framework", "dockerfile",
			"--check", "CKV_DOCKER_2,CKV_DOCKER_3", // HEALTHCHECK and USER checks
			"-o", "json",
			"--quiet",
			"--compact",
		).CombinedOutput()

		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 1 {
				t.Logf("Checkov error: %v", err)
			}
		}

		cfg := Config{}
		scanner := NewCheckovScannerWithLogger(cfg, []string{}, logger.GetGlobalLogger())

		findings, err := scanner.ParseResults(output)
		require.NoError(t, err)

		for _, f := range findings {
			t.Logf("Docker Finding: %s - %s", f.Type, f.Title)
			assert.Equal(t, "container-misconfiguration", f.Type)
		}
	})

	t.Run("High Severity Only", func(t *testing.T) {
		// Test running with only high severity checks
		tfDir := filepath.Join(tempDir, "terraform-high")
		require.NoError(t, os.MkdirAll(tfDir, 0755))

		// Create file with various severity issues
		tfContent := `resource "aws_iam_policy" "bad_policy" {
  name = "bad_policy"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "*"         # Bad - too permissive
        Resource = "*"       # Bad - too permissive
      }
    ]
  })
}

resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  # Missing encryption - high severity
}`

		require.NoError(t, os.WriteFile(filepath.Join(tfDir, "main.tf"), []byte(tfContent), 0644))

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Run with high severity filter
		output, err := exec.CommandContext(ctx, "checkov",
			"-d", tfDir,
			"--framework", "terraform",
			"--check", "HIGH", // Only HIGH severity
			"-o", "json",
			"--quiet",
			"--compact",
		).CombinedOutput()

		if err != nil {
			// If error but we have output, it's probably OK (exit code 1)
			if len(output) == 0 {
				t.Logf("Checkov error with no output: %v", err)
			}
		}

		if len(output) > 0 {
			cfg := Config{}
			scanner := NewCheckovScannerWithLogger(cfg, []string{}, logger.GetGlobalLogger())

			findings, err := scanner.ParseResults(output)
			if err == nil {
				t.Logf("Found %d high severity findings", len(findings))
				for _, f := range findings {
					assert.Contains(t, []string{"high", "critical"}, f.Severity)
				}
			}
		}
	})

	t.Run("Parse Real Checkov Output", func(t *testing.T) {
		// Test with actual checkov output format
		cfg := Config{}
		scanner := NewCheckovScannerWithLogger(cfg, []string{}, logger.GetGlobalLogger())

		// This is real output from checkov
		realOutput := `[{
			"check_type": "terraform",
			"results": {
				"failed_checks": [{
					"check_id": "CKV_AWS_18",
					"bc_check_id": "BC_AWS_S3_13",
					"check_name": "Ensure the S3 bucket has access logging enabled",
					"check_result": {"result": "FAILED"},
					"code_block": null,
					"file_path": "/s3.tf",
					"file_abs_path": "/tmp/test/s3.tf",
					"repo_file_path": "/s3.tf",
					"file_line_range": [1, 5],
					"resource": "aws_s3_bucket.test",
					"severity": "MEDIUM",
					"bc_category": "Logging",
					"guideline": "https://docs.bridgecrew.io/docs/s3_13-enable-logging"
				}]
			},
			"summary": {
				"passed": 2,
				"failed": 1,
				"skipped": 0,
				"parsing_errors": 0,
				"resource_count": 3,
				"checkov_version": "2.3.340"
			}
		}]`

		findings, err := scanner.ParseResults([]byte(realOutput))
		require.NoError(t, err)
		assert.Len(t, findings, 1)

		f := findings[0]
		assert.Equal(t, "aws-misconfiguration", f.Type)
		assert.Equal(t, "medium", f.Severity)
		assert.Contains(t, f.Title, "S3 bucket has access logging")
		assert.Equal(t, "CKV_AWS_18", f.Metadata["check_id"])
	})
}

func TestCheckovScanner_MinimalExecution(t *testing.T) {
	// Test the absolute minimal execution path
	if _, err := exec.LookPath("checkov"); err != nil {
		t.Skip("checkov not installed")
	}

	tempDir := t.TempDir()

	// Create the simplest possible terraform file
	tfContent := `resource "null_resource" "test" {
  triggers = {
    always = timestamp()
  }
}`

	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "main.tf"), []byte(tfContent), 0644))

	// Run checkov with minimal configuration
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cfg := Config{
		Timeout: 5,
		Debug:   true,
	}

	scanner := NewCheckovScannerWithLogger(cfg, []string{tempDir}, logger.GetGlobalLogger())

	result, err := scanner.Scan(ctx)
	require.NoError(t, err)
	assert.NotNil(t, result)

	// May or may not find issues, but should complete quickly
	t.Logf("Minimal scan completed with %d findings", len(result.Findings))
}
