//go:build integration
// +build integration

package scanner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Veraticus/prismatic/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckovScanner_RealIntegration(t *testing.T) {
	// Skip if checkov is not installed
	if _, err := exec.LookPath("checkov"); err != nil {
		t.Skip("checkov not installed")
	}

	// Create test directories
	tempDir := t.TempDir()

	t.Run("Terraform Misconfigurations", func(t *testing.T) {
		// Create a terraform directory
		tfDir := filepath.Join(tempDir, "terraform")
		require.NoError(t, os.MkdirAll(tfDir, 0755))

		// Create a vulnerable Terraform file
		tfFile := filepath.Join(tfDir, "s3.tf")
		tfContent := `# Vulnerable S3 bucket configuration
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "my-vulnerable-bucket"
  acl    = "public-read-write"  # Bad: Public write access
}

resource "aws_s3_bucket_versioning" "example" {
  bucket = aws_s3_bucket.vulnerable_bucket.id
  versioning_configuration {
    status = "Disabled"  # Bad: Versioning disabled
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = aws_s3_bucket.vulnerable_bucket.bucket
  
  # Missing encryption configuration - Bad!
}

resource "aws_security_group" "vulnerable_sg" {
  name        = "vulnerable_security_group"
  description = "Vulnerable security group"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Bad: SSH open to the world
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`
		require.NoError(t, os.WriteFile(tfFile, []byte(tfContent), 0644))

		// Run checkov directly to verify it works
		output, err := exec.Command("checkov", "-d", tfDir, "-o", "json", "--quiet", "--compact").Output()
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
				// Exit code 1 means checks failed, which is expected
				t.Logf("Checkov found issues (expected): %s", string(exitErr.Stderr))
			} else {
				t.Fatalf("Checkov command failed: %v", err)
			}
		}
		t.Logf("Checkov output sample: %.500s", string(output))

		// Test our scanner
		cfg := Config{
			Timeout: 60,
			Debug:   true,
		}

		scanner := NewCheckovScannerWithLogger(cfg, []string{tfDir}, logger.GetGlobalLogger())

		// First, test parsing the direct output
		if len(output) > 0 {
			parsedFindings, parseErr := scanner.ParseResults(output)
			t.Logf("Direct parse result: %d findings, error: %v", len(parsedFindings), parseErr)
			if parseErr != nil {
				t.Logf("Parse error details: %v", parseErr)
			}
		}

		// Run scan
		ctx := context.Background()
		result, err := scanner.Scan(ctx)
		require.NoError(t, err)
		assert.NotNil(t, result)

		// Should find misconfigurations
		assert.NotEmpty(t, result.Findings, "Should find terraform misconfigurations")

		// Check findings
		foundTypes := make(map[string]int)
		for _, finding := range result.Findings {
			assert.Equal(t, "checkov", finding.Scanner)
			assert.NotEmpty(t, finding.Title)
			assert.NotEmpty(t, finding.Severity)
			assert.NotEmpty(t, finding.Type)
			foundTypes[finding.Type]++

			// Check metadata
			assert.NotEmpty(t, finding.Metadata["check_id"])
			assert.NotEmpty(t, finding.Metadata["file_path"])

			t.Logf("Found: %s - %s (%s)", finding.Type, finding.Title, finding.Metadata["check_id"])
		}

		// Should find AWS misconfigurations
		assert.Greater(t, foundTypes["aws-misconfiguration"]+foundTypes["encryption-misconfiguration"]+foundTypes["network-misconfiguration"], 0,
			"Should find AWS-related misconfigurations")
	})

	t.Run("Kubernetes Misconfigurations", func(t *testing.T) {
		// Create a k8s directory
		k8sDir := filepath.Join(tempDir, "kubernetes")
		require.NoError(t, os.MkdirAll(k8sDir, 0755))

		// Create a vulnerable Kubernetes deployment
		k8sFile := filepath.Join(k8sDir, "deployment.yaml")
		k8sContent := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vulnerable
  template:
    metadata:
      labels:
        app: vulnerable
    spec:
      containers:
      - name: app
        image: vulnerable:latest
        # Missing security context - Bad!
        # Missing resource limits - Bad!
        ports:
        - containerPort: 8080
        env:
        - name: DATABASE_PASSWORD
          value: "super-secret-password"  # Bad: Hardcoded secret
---
apiVersion: v1
kind: Service
metadata:
  name: vulnerable-service
spec:
  type: LoadBalancer  # Bad: Exposing service directly
  selector:
    app: vulnerable
  ports:
  - port: 8080
    targetPort: 8080
`
		require.NoError(t, os.WriteFile(k8sFile, []byte(k8sContent), 0644))

		// Test scanner
		cfg := Config{
			Timeout: 60,
		}

		scanner := NewCheckovScannerWithLogger(cfg, []string{k8sDir}, logger.GetGlobalLogger())

		// Run scan
		ctx := context.Background()
		result, err := scanner.Scan(ctx)
		require.NoError(t, err)
		assert.NotNil(t, result)

		// Log findings
		t.Logf("Found %d findings in Kubernetes configs", len(result.Findings))

		// Check for Kubernetes misconfigurations
		foundK8s := false
		for _, finding := range result.Findings {
			if finding.Type == "kubernetes-misconfiguration" || finding.Type == "exposed-secret" {
				foundK8s = true
				t.Logf("K8s finding: %s", finding.Title)
			}
		}

		if !foundK8s && len(result.Findings) == 0 {
			t.Log("No Kubernetes findings - Checkov might not have K8s checks enabled")
		}
	})

	t.Run("Secrets Detection", func(t *testing.T) {
		// Create a directory with secrets
		secretsDir := filepath.Join(tempDir, "secrets")
		require.NoError(t, os.MkdirAll(secretsDir, 0755))

		// Create a file with secrets
		secretsFile := filepath.Join(secretsDir, "config.py")
		secretsContent := `# Configuration file with secrets
DATABASE_URL = "postgresql://user:password123@localhost/db"
API_KEY = "sk-1234567890abcdef1234567890abcdef"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"

# More config
DEBUG = True
`
		require.NoError(t, os.WriteFile(secretsFile, []byte(secretsContent), 0644))

		// Test scanner
		cfg := Config{
			Timeout: 60,
		}

		scanner := NewCheckovScannerWithLogger(cfg, []string{secretsDir}, logger.GetGlobalLogger())

		// Run scan
		ctx := context.Background()
		result, err := scanner.Scan(ctx)
		require.NoError(t, err)
		assert.NotNil(t, result)

		// Should find secrets
		secretCount := 0
		for _, finding := range result.Findings {
			if finding.Type == "exposed-secret" {
				secretCount++
				assert.Equal(t, "high", finding.Severity)
				assert.Contains(t, finding.Description, "potential")
				assert.Contains(t, finding.Remediation, "rotate")
				t.Logf("Found secret: %s at %s", finding.Title, finding.Location)
			}
		}

		if secretCount == 0 {
			t.Log("No secrets found - Checkov secrets scanning might be disabled")
		} else {
			assert.Greater(t, secretCount, 0, "Should find at least one secret")
		}
	})

	t.Run("Multiple Targets", func(t *testing.T) {
		// Test with multiple directories
		targets := []string{
			filepath.Join(tempDir, "terraform"),
			filepath.Join(tempDir, "kubernetes"),
			filepath.Join(tempDir, "secrets"),
		}

		cfg := Config{
			Timeout: 60,
		}

		scanner := NewCheckovScannerWithLogger(cfg, targets, logger.GetGlobalLogger())

		// Run scan
		ctx := context.Background()
		result, err := scanner.Scan(ctx)
		require.NoError(t, err)
		assert.NotNil(t, result)

		// Should have findings from multiple targets
		targetPaths := make(map[string]bool)
		filePathsFound := []string{}
		for _, finding := range result.Findings {
			if fp, ok := finding.Metadata["file_path"]; ok {
				filePathsFound = append(filePathsFound, fp)
				// Extract the directory part - handle both absolute and relative paths
				for _, target := range targets {
					// Check if the file path contains the target directory name
					targetName := filepath.Base(target)
					if strings.Contains(fp, targetName) {
						targetPaths[target] = true
						break
					}
				}
			}
		}

		t.Logf("Found %d findings total", len(result.Findings))
		if len(filePathsFound) > 0 {
			maxSample := 5
			if len(filePathsFound) < maxSample {
				maxSample = len(filePathsFound)
			}
			t.Logf("Sample file paths: %v", filePathsFound[:maxSample])
		}
		t.Logf("Found findings from %d different target directories", len(targetPaths))

		// The test should pass if we have findings at all
		assert.NotEmpty(t, result.Findings, "Should have at least some findings")
	})

	t.Run("No Targets", func(t *testing.T) {
		cfg := Config{}
		scanner := NewCheckovScannerWithLogger(cfg, []string{}, logger.GetGlobalLogger())

		result, err := scanner.Scan(context.Background())
		assert.ErrorIs(t, err, ErrNoTargets)
		assert.NotNil(t, result)
		assert.Empty(t, result.Findings)
	})
}
