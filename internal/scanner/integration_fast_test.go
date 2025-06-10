//go:build integration
// +build integration

package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNucleiIntegrationMinimal tests Nuclei with minimal configuration for sub-5-second execution
func TestNucleiIntegrationMinimal(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check if nuclei is available
	if _, err := exec.LookPath("nuclei"); err != nil {
		t.Skip("nuclei not found in PATH")
	}

	// Start a minimal test server
	server := startMinimalTestServer(t)
	defer server.Close()

	// Create temporary directory for test config
	cfg := Config{
		Env: map[string]string{
			"HOME": t.TempDir(),
		},
	}
	// scanner := NewNucleiScanner(cfg, []string{server.URL})
	// Note: For this test, we run nuclei directly to have full control over flags

	// Create a custom context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Run scan
	start := time.Now()

	// For fast testing, we'll run nuclei directly with minimal options
	cmd := exec.CommandContext(ctx, "nuclei",
		"-u", server.URL,
		"-j",                    // JSON output
		"-tags", "panel,config", // Only quick detection templates
		"-timeout", "3", // 3 second timeout per request
		"-rate-limit", "100", // Fast rate for local testing
		"-c", "10", // Limited concurrency
		"-duc",    // Disable update check
		"-silent", // Silent mode
	)

	// Set environment from config
	if cfg.Env != nil {
		cmd.Env = os.Environ()
		for k, v := range cfg.Env {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
		}
	}

	output, _ := cmd.CombinedOutput()
	duration := time.Since(start)

	// Should complete quickly
	assert.Less(t, duration, 5*time.Second, "Scan took too long: %v", duration)

	// Log output for debugging
	t.Logf("Nuclei scan completed in %v", duration)
	if len(output) > 0 {
		t.Logf("Output preview: %.200s", output)
	}
}

// TestCheckovIntegrationMinimal tests Checkov with minimal configuration for sub-5-second execution
func TestCheckovIntegrationMinimal(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check if checkov is available
	if _, err := exec.LookPath("checkov"); err != nil {
		t.Skip("checkov not found in PATH")
	}

	// Create minimal test files
	tmpDir := t.TempDir()

	// Minimal Terraform file with 2 issues
	tfContent := `
resource "aws_s3_bucket" "test" {
  bucket = "test-bucket"
}

resource "aws_security_group" "test" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`
	err := os.WriteFile(filepath.Join(tmpDir, "main.tf"), []byte(tfContent), 0644)
	require.NoError(t, err)

	// Note: For this test, we run checkov directly to have full control over flags

	// Run scan with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()

	// For fast testing, run checkov directly with minimal options
	cmd := exec.CommandContext(ctx, "checkov",
		"-d", tmpDir,
		"--framework", "terraform", // Single framework
		"--check", "CKV_AWS_18,CKV_AWS_24", // Only 2 specific checks
		"--output", "json",
		"--quiet",
		"--compact",
	)

	output, _ := cmd.CombinedOutput()
	duration := time.Since(start)

	// Should complete quickly
	assert.Less(t, duration, 5*time.Second, "Scan took too long: %v", duration)

	// Should have found issues
	assert.Contains(t, string(output), "failed_checks")

	t.Logf("Checkov scan completed in %v", duration)
}

// TestScannerIntegrationExamples provides example commands for manual testing
func TestScannerIntegrationExamples(t *testing.T) {
	t.Log("=== Nuclei Fast Execution Examples ===")
	t.Log("")
	t.Log("1. CVE Detection Only (2-3 seconds):")
	t.Log("   nuclei -tags cve -severity critical,high -rl 100 -c 25 -timeout 5 -u https://example.com")
	t.Log("")
	t.Log("2. Technology Detection (1-2 seconds):")
	t.Log("   nuclei -tags tech -rl 100 -c 50 -timeout 3 -u https://example.com")
	t.Log("")
	t.Log("3. Specific Vulnerabilities (2-4 seconds):")
	t.Log("   nuclei -tags sqli,xss,rce -severity high,critical -rl 50 -timeout 5 -u https://example.com")
	t.Log("")
	t.Log("4. Single Template (< 1 second):")
	t.Log("   nuclei -t cves/2021/CVE-2021-44228.yaml -rl 50 -u https://example.com")
	t.Log("")
	t.Log("=== Checkov Fast Execution Examples ===")
	t.Log("")
	t.Log("1. High Severity Only (1-2 seconds):")
	t.Log("   checkov -d . --framework terraform --check HIGH --output json --quiet")
	t.Log("")
	t.Log("2. Specific Checks (< 1 second):")
	t.Log("   checkov -d . --check CKV_AWS_18,CKV_AWS_24 --output json --compact")
	t.Log("")
	t.Log("3. Single Framework (1-2 seconds):")
	t.Log("   checkov -d . --framework dockerfile --output json --quiet")
	t.Log("")
	t.Log("4. Skip Low Severity (2-3 seconds):")
	t.Log("   checkov -d . --skip-check LOW --framework terraform --output json")
}

// startMinimalTestServer creates a very simple HTTP server for testing
func startMinimalTestServer(t *testing.T) *testHTTPServer {
	mux := http.NewServeMux()

	// Single endpoint that responds quickly
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "TestServer/1.0")
		fmt.Fprintf(w, "<html><body><h1>Test Server</h1></body></html>")
	})

	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body><h1>Admin Panel</h1></body></html>")
	})

	// Find free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &http.Server{Handler: mux}

	go func() {
		_ = server.Serve(listener)
	}()

	// Minimal wait
	time.Sleep(50 * time.Millisecond)

	return &testHTTPServer{
		Server: server,
		URL:    fmt.Sprintf("http://%s", listener.Addr().String()),
	}
}

type testHTTPServer struct {
	*http.Server
	URL string
}
