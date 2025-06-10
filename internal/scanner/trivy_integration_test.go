//go:build integration
// +build integration

package scanner

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Veraticus/prismatic/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTrivyScanner_RealIntegration(t *testing.T) {
	// Skip if trivy is not installed
	if _, err := exec.LookPath("trivy"); err != nil {
		t.Skip("trivy not installed")
	}

	// Create a test directory
	tempDir := t.TempDir()

	// Test 1: Vulnerable Dockerfile
	t.Run("Vulnerable Dockerfile", func(t *testing.T) {
		// Create a Dockerfile with known vulnerabilities
		dockerfile := filepath.Join(tempDir, "Dockerfile")
		dockerfileContent := `FROM ubuntu:20.04
RUN apt-get update && apt-get install -y \
    curl=7.68.0-1ubuntu2 \
    openssl=1.1.1f-1ubuntu2
EXPOSE 8080
`
		require.NoError(t, os.WriteFile(dockerfile, []byte(dockerfileContent), 0644))

		// Run trivy directly to see what it produces
		output, err := exec.Command("trivy", "--format", "json", "--quiet", "--exit-code", "0", "fs", tempDir).Output()
		require.NoError(t, err, "trivy command failed")

		t.Logf("Trivy direct output sample: %.500s", string(output))

		// Parse to verify structure
		var report TrivyReport
		require.NoError(t, json.Unmarshal(output, &report))
		// Note: Results might be empty for simple Dockerfiles without vulnerabilities

		// Now test our scanner
		cfg := Config{
			WorkingDir: tempDir,
			Timeout:    300,
		}

		scanner := NewTrivyScannerWithLogger(cfg, []string{tempDir}, logger.GetGlobalLogger())

		// Run scan
		ctx := context.Background()
		result, err := scanner.Scan(ctx)
		require.NoError(t, err)
		assert.NotNil(t, result)

		// Log what we found
		t.Logf("Scanner found %d findings", len(result.Findings))

		// For Dockerfiles, we might not find vulnerabilities but we should test config scan
		if len(result.Findings) == 0 {
			// Try config scan instead
			configOutput, err := exec.Command("trivy", "--format", "json", "--quiet", "--exit-code", "0", "config", tempDir).Output()
			t.Logf("Config scan found issues: %v", err == nil && strings.Contains(string(configOutput), "Misconfigurations"))
		}

		// Check findings
		foundTypes := make(map[string]int)
		for _, finding := range result.Findings {
			assert.Equal(t, "trivy", finding.Scanner)
			assert.NotEmpty(t, finding.Title)
			assert.NotEmpty(t, finding.Severity)
			foundTypes[finding.Type]++

			t.Logf("Found %s: %s (severity: %s)", finding.Type, finding.Title, finding.Severity)
		}

		// We expect to find misconfigurations
		assert.Greater(t, foundTypes["misconfiguration"], 0, "Should find at least one misconfiguration")
	})

	// Test 2: Vulnerable package.json
	t.Run("Vulnerable package.json", func(t *testing.T) {
		// Create a package.json with known vulnerable dependencies
		packageDir := filepath.Join(tempDir, "nodejs-app")
		require.NoError(t, os.MkdirAll(packageDir, 0755))

		packageJSON := filepath.Join(packageDir, "package.json")
		packageContent := `{
  "name": "test-app",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "4.17.4",
    "jquery": "2.2.4",
    "express": "4.15.0"
  }
}
`
		require.NoError(t, os.WriteFile(packageJSON, []byte(packageContent), 0644))

		// Create package-lock.json for better detection
		packageLock := filepath.Join(packageDir, "package-lock.json")
		packageLockContent := `{
  "name": "test-app",
  "version": "1.0.0",
  "lockfileVersion": 1,
  "requires": true,
  "dependencies": {
    "lodash": {
      "version": "4.17.4",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.4.tgz"
    },
    "jquery": {
      "version": "2.2.4",
      "resolved": "https://registry.npmjs.org/jquery/-/jquery-2.2.4.tgz"
    },
    "express": {
      "version": "4.15.0",
      "resolved": "https://registry.npmjs.org/express/-/express-4.15.0.tgz"
    }
  }
}
`
		require.NoError(t, os.WriteFile(packageLock, []byte(packageLockContent), 0644))

		// Run trivy directly
		output, err := exec.Command("trivy", "--format", "json", "--quiet", "--exit-code", "0", "fs", packageDir).Output()
		if err != nil {
			t.Logf("Trivy stderr: %s", err.Error())
		}

		t.Logf("Trivy package.json scan output sample: %.500s", string(output))

		// Create scanner for this directory
		cfg := Config{
			WorkingDir: packageDir,
			Timeout:    300,
		}

		scanner := NewTrivyScannerWithLogger(cfg, []string{packageDir}, logger.GetGlobalLogger())

		// Run scan
		ctx := context.Background()
		result, err := scanner.Scan(ctx)
		require.NoError(t, err)
		assert.NotNil(t, result)

		// Log findings for debugging
		t.Logf("Found %d total findings", len(result.Findings))

		// Check for vulnerabilities
		vulnCount := 0
		for _, finding := range result.Findings {
			if finding.Type == "vulnerability" {
				vulnCount++
				// Extract package name from the title (e.g., "CVE-2021-23337: HIGH vulnerability in lodash")
				titleParts := strings.Split(finding.Title, " in ")
				if len(titleParts) > 1 {
					pkgName := titleParts[len(titleParts)-1]
					assert.Contains(t, []string{"lodash", "jquery", "express"}, pkgName)
				}
				t.Logf("Found vulnerability in %s: %s", finding.Resource, finding.Title)
			}
		}

		if vulnCount == 0 {
			t.Log("No vulnerabilities found - this might be expected if trivy's vulnerability database is not updated")
		}
	})

	// Test 3: Test with secrets
	t.Run("Secrets in code", func(t *testing.T) {
		// Create a directory with secrets
		secretsDir := filepath.Join(tempDir, "secrets-test")
		require.NoError(t, os.MkdirAll(secretsDir, 0755))

		// Create a file with secrets
		configFile := filepath.Join(secretsDir, "config.yaml")
		configContent := `apiVersion: v1
kind: Secret
metadata:
  name: mysecret
data:
  username: YWRtaW4=
  password: MWYyZDFlMmU2N2Rm
---
database:
  host: localhost
  password: "super-secret-password-123"
  aws_access_key: "AKIAJ7Q2VKXYKDT5WHFQ"
`
		require.NoError(t, os.WriteFile(configFile, []byte(configContent), 0644))

		// Run trivy directly
		output, err := exec.Command("trivy", "--format", "json", "--quiet", "--exit-code", "0", "fs", secretsDir).Output()
		t.Logf("Trivy secrets scan output sample: %.500s", string(output))

		// Create scanner
		cfg := Config{
			WorkingDir: secretsDir,
			Timeout:    300,
		}

		scanner := NewTrivyScannerWithLogger(cfg, []string{secretsDir}, logger.GetGlobalLogger())

		// Run scan
		ctx := context.Background()
		result, err := scanner.Scan(ctx)
		require.NoError(t, err)
		assert.NotNil(t, result)

		// Check for secrets or misconfigurations
		foundSecrets := 0
		foundMisconfigs := 0
		for _, finding := range result.Findings {
			if finding.Type == "secret" {
				foundSecrets++
				t.Logf("Found secret: %s at %s", finding.Title, finding.Location)
			} else if finding.Type == "misconfiguration" {
				foundMisconfigs++
				t.Logf("Found misconfiguration: %s", finding.Title)
			}
		}

		// Should find either secrets or misconfigurations
		assert.Greater(t, foundSecrets+foundMisconfigs, 0, "Should find at least one issue")
	})

	// Test 4: Multiple targets
	t.Run("Multiple targets", func(t *testing.T) {
		targets := []string{tempDir, filepath.Join(tempDir, "nodejs-app")}

		cfg := Config{
			WorkingDir: tempDir,
			Timeout:    300,
		}

		scanner := NewTrivyScannerWithLogger(cfg, targets, logger.GetGlobalLogger())

		// Run scan
		ctx := context.Background()
		result, err := scanner.Scan(ctx)
		require.NoError(t, err)
		assert.NotNil(t, result)

		// Should have findings from multiple targets
		targetSet := make(map[string]bool)
		for _, finding := range result.Findings {
			targetSet[finding.Resource] = true
		}

		t.Logf("Found findings from %d unique targets", len(targetSet))
		assert.GreaterOrEqual(t, len(targetSet), 1, "Should have findings from at least one target")
	})
}

// TestTrivyDockerImage_Integration tests Trivy scanning of Docker images
func TestTrivyDockerImage_Integration(t *testing.T) {
	// Skip if trivy is not installed
	if _, err := exec.LookPath("trivy"); err != nil {
		t.Skip("trivy not installed")
	}

	// Use a small, known vulnerable image
	testImage := "alpine:3.7" // Old Alpine version with known CVEs

	// First, run trivy directly to see output
	output, err := exec.Command("trivy", "--format", "json", "--quiet", "--exit-code", "0", "image", testImage).Output()
	if err != nil {
		// Trivy might fail if it can't pull the image
		t.Skipf("Could not scan test image %s: %v", testImage, err)
	}

	t.Logf("Trivy image scan output sample: %.500s", string(output))

	// Parse to verify structure
	var report TrivyReport
	require.NoError(t, json.Unmarshal(output, &report))

	// Create scanner
	cfg := Config{
		Timeout: 300,
	}

	scanner := NewTrivyScannerWithLogger(cfg, []string{testImage}, logger.GetGlobalLogger())

	// Run scan
	ctx := context.Background()
	result, err := scanner.Scan(ctx)
	require.NoError(t, err)
	assert.NotNil(t, result)

	// Should find vulnerabilities in the old Alpine image
	vulnCount := 0
	severityCounts := make(map[string]int)
	for _, finding := range result.Findings {
		if finding.Type == "vulnerability" {
			vulnCount++
			severityCounts[finding.Severity]++

			// Verify vulnerability structure
			assert.NotEmpty(t, finding.Title)
			assert.NotEmpty(t, finding.Description)
			assert.NotEmpty(t, finding.Metadata["installed_version"])
			assert.Contains(t, finding.Title, "CVE-") // Should have CVE ID
		}
	}

	t.Logf("Found %d vulnerabilities: %+v", vulnCount, severityCounts)
	assert.Greater(t, vulnCount, 0, "Should find vulnerabilities in old Alpine image")
}
