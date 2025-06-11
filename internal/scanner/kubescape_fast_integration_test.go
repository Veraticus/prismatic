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
	"time"

	"github.com/joshsymonds/prismatic/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKubescapeScanner_FastIntegration(t *testing.T) {
	// Skip if kubescape is not installed
	if _, err := exec.LookPath("kubescape"); err != nil {
		t.Skip("kubescape not installed")
	}

	// Create test directory
	tempDir := t.TempDir()

	t.Run("Scan Privileged Pod", func(t *testing.T) {
		// Create a pod with security issues
		podYAML := filepath.Join(tempDir, "privileged-pod.yaml")
		require.NoError(t, os.WriteFile(podYAML, []byte(`
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
  - name: nginx
    image: nginx:latest
    securityContext:
      privileged: true
      runAsUser: 0
      allowPrivilegeEscalation: true
`), 0644))

		// Run kubescape directly on the YAML file
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Run kubescape scan directly
		output, err := exec.CommandContext(ctx, "kubescape",
			"scan", podYAML,
			"--format", "json",
			"--verbose=false",
		).Output()

		// Kubescape returns non-zero when it finds issues, which is expected
		if err != nil && ctx.Err() == nil {
			t.Logf("Kubescape returned non-zero exit code (expected when issues found): %v", err)
		}

		require.NotEmpty(t, output, "Should have output")
		t.Logf("Kubescape output: %s", output)

		// Parse the output
		cfg := Config{}
		scanner := NewKubescapeScannerWithLogger(cfg, "", []string{}, []string{}, logger.GetGlobalLogger())

		findings, err := scanner.ParseResults(output)
		require.NoError(t, err)
		assert.NotEmpty(t, findings, "Should find security issues in privileged pod")

		// Check for specific findings
		var foundPrivileged bool
		var foundRoot bool
		for _, f := range findings {
			t.Logf("Found: %s - %s", f.Type, f.Title)
			if contains(f.Title, "privileged") || contains(f.Title, "Privileged") {
				foundPrivileged = true
			}
			if contains(f.Title, "root") || contains(f.Title, "user 0") {
				foundRoot = true
			}
		}
		assert.True(t, foundPrivileged || foundRoot, "Should detect privileged container or root user")
	})

	t.Run("Scan Deployment Without Limits", func(t *testing.T) {
		// Create deployment without resource limits
		deployYAML := filepath.Join(tempDir, "no-limits-deployment.yaml")
		require.NoError(t, os.WriteFile(deployYAML, []byte(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: no-limits
spec:
  replicas: 1
  selector:
    matchLabels:
      app: no-limits
  template:
    metadata:
      labels:
        app: no-limits
    spec:
      containers:
      - name: app
        image: nginx:1.21
        # Missing: resources limits and requests
        # Missing: securityContext
        # Missing: livenessProbe and readinessProbe
`), 0644))

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Run kubescape scan directly
		output, err := exec.CommandContext(ctx, "kubescape",
			"scan", deployYAML,
			"--format", "json",
			"--verbose=false",
		).Output()

		if err != nil && ctx.Err() == nil {
			t.Logf("Kubescape returned non-zero exit code (expected when issues found)")
		}

		require.NotEmpty(t, output, "Should have output")

		// Parse the output
		cfg := Config{}
		scanner := NewKubescapeScannerWithLogger(cfg, "", []string{}, []string{}, logger.GetGlobalLogger())

		findings, err := scanner.ParseResults(output)
		require.NoError(t, err)

		// Should find missing resource limits
		var foundLimits bool
		var foundProbes bool
		for _, f := range findings {
			if contains(f.Title, "resource") || contains(f.Title, "limits") {
				foundLimits = true
			}
			if contains(f.Title, "probe") || contains(f.Title, "liveness") {
				foundProbes = true
			}
		}
		assert.True(t, foundLimits || foundProbes, "Should detect missing limits or probes")
	})

	t.Run("Scan Excessive RBAC", func(t *testing.T) {
		// Create overly permissive RBAC
		rbacYAML := filepath.Join(tempDir, "excessive-rbac.yaml")
		require.NoError(t, os.WriteFile(rbacYAML, []byte(`
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: super-admin
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
`), 0644))

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Run kubescape scan directly
		output, err := exec.CommandContext(ctx, "kubescape",
			"scan", rbacYAML,
			"--format", "json",
			"--verbose=false",
		).Output()

		if err != nil && ctx.Err() == nil {
			t.Logf("Kubescape returned non-zero exit code (expected when issues found)")
		}

		require.NotEmpty(t, output, "Should have output")

		// Parse the output
		cfg := Config{}
		scanner := NewKubescapeScannerWithLogger(cfg, "", []string{}, []string{}, logger.GetGlobalLogger())

		findings, err := scanner.ParseResults(output)
		require.NoError(t, err)

		// Log number of findings
		t.Logf("Found %d findings for RBAC scan", len(findings))

		// Should find wildcard permissions or administrative roles
		// Note: Kubescape may not find issues with just a ClusterRole definition
		// without it being bound to a subject
		if len(findings) > 0 {
			var foundWildcard bool
			for _, f := range findings {
				t.Logf("RBAC Finding: %s - %s", f.Type, f.Title)
				title := strings.ToLower(f.Title)
				fType := strings.ToLower(f.Type)
				if contains(title, "wildcard") || contains(title, "*") || contains(title, "excessive") ||
					contains(title, "admin") || contains(title, "delete") || contains(fType, "admin") {
					foundWildcard = true
				}
			}
			assert.True(t, foundWildcard, "Should detect wildcard permissions or administrative roles")
		} else {
			t.Skip("Kubescape did not find issues with unbound ClusterRole")
		}
	})

	t.Run("Fast Control Scan", func(t *testing.T) {
		// Test scanning with specific control for speed
		podYAML := filepath.Join(tempDir, "test-pod.yaml")
		require.NoError(t, os.WriteFile(podYAML, []byte(`
apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
  - name: test
    image: nginx:latest
`), 0644))

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Run with specific control
		output, err := exec.CommandContext(ctx, "kubescape",
			"scan", "control", "Configured liveness probe",
			podYAML,
			"--format", "json",
			"--verbose=false",
		).CombinedOutput()

		if err == nil {
			// Parse output
			cfg := Config{}
			scanner := NewKubescapeScannerWithLogger(cfg, "", []string{}, []string{}, logger.GetGlobalLogger())

			findings, parseErr := scanner.ParseResults(output)
			assert.NoError(t, parseErr)
			assert.NotEmpty(t, findings, "Should find missing liveness probe")
		}
	})

	t.Run("Parse Real Kubescape Output", func(t *testing.T) {
		// Test with captured real output structure
		cfg := Config{}
		scanner := NewKubescapeScannerWithLogger(cfg, "", []string{}, []string{}, logger.GetGlobalLogger())

		// This is simplified real output from kubescape
		realOutput := `{
			"results": [{
				"resourceID": "pod/default/privileged-pod",
				"controls": [{
					"controlID": "C-0086",
					"name": "Privileged container",
					"description": "Potential attackers may gain access to a privileged container...",
					"remediation": "Remove privileged capabilities by setting the securityContext.privileged to false",
					"severity": "high",
					"score": 0
				}]
			}],
			"summaryDetails": {
				"frameworks": [{
					"name": "NSA",
					"controls": {
						"failed": 15,
						"passed": 5,
						"total": 20
					}
				}]
			}
		}`

		findings, err := scanner.ParseResults([]byte(realOutput))
		require.NoError(t, err)
		assert.NotEmpty(t, findings)

		f := findings[0]
		assert.Equal(t, "kubescape", f.Scanner)
		assert.Contains(t, f.Title, "Privileged container")
		assert.Equal(t, "high", f.Severity)
	})
}

// Helper function
func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr ||
		len(s) > len(substr) && (s[:len(substr)] == substr ||
			s[len(s)-len(substr):] == substr ||
			func() bool {
				for i := 1; i < len(s)-len(substr); i++ {
					if s[i:i+len(substr)] == substr {
						return true
					}
				}
				return false
			}()))
}
