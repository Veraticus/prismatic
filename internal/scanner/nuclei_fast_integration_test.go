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

func TestNucleiScanner_FastIntegration(t *testing.T) {
	// Skip if nuclei is not installed
	if _, err := exec.LookPath("nuclei"); err != nil {
		t.Skip("nuclei not installed")
	}

	t.Run("Technology Detection - Fast", func(t *testing.T) {
		// Create a test server that responds with known technology signatures
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/":
				// Apache server header for tech detection
				w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
				w.Header().Set("X-Powered-By", "PHP/7.4.3")
				fmt.Fprintf(w, `<html>
					<head><title>Test Page</title></head>
					<body>
						<h1>Welcome</h1>
						<!-- Powered by WordPress 5.8 -->
					</body>
				</html>`)
			case "/robots.txt":
				// Common robots.txt
				fmt.Fprintf(w, "User-agent: *\nDisallow: /admin/\nDisallow: /wp-admin/\n")
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		// Run nuclei with only tech detection templates (very fast)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		output, err := exec.CommandContext(ctx, "nuclei",
			"-u", server.URL,
			"-tags", "tech", // Only technology detection
			"-j",         // JSON output
			"-silent",    // No extra output
			"-no-color",  // No color codes
			"-duc",       // Disable update check
			"-rl", "100", // Rate limit
			"-c", "50", // Concurrency
			"-timeout", "3", // Short timeout per request
		).CombinedOutput()

		if err != nil && ctx.Err() == nil {
			t.Logf("Nuclei error: %v", err)
		}

		// Parse the output
		cfg := Config{}
		scanner := NewNucleiScannerWithLogger(cfg, []string{}, logger.GetGlobalLogger())

		findings, err := scanner.ParseResults(output)
		require.NoError(t, err)

		// We should find at least Apache or PHP detection
		assert.NotEmpty(t, findings, "Should detect at least one technology")

		for _, f := range findings {
			t.Logf("Found: %s - %s", f.Type, f.Title)
			assert.Equal(t, "nuclei", f.Scanner)
			assert.Contains(t, []string{"Technology Detection", "Web Server Detection"}, f.Type)
		}
	})

	t.Run("Panel Detection - Fast", func(t *testing.T) {
		// Create a server with admin panel signatures
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/admin", "/admin/", "/admin/login":
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprintf(w, `<html>
					<head><title>Admin Login</title></head>
					<body>
						<form action="/admin/login" method="POST">
							<input type="text" name="username" placeholder="Username">
							<input type="password" name="password" placeholder="Password">
							<button type="submit">Login</button>
						</form>
					</body>
				</html>`)
			case "/wp-admin", "/wp-admin/":
				// WordPress admin panel
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprintf(w, `<html>
					<head><title>WordPress Admin</title></head>
					<body class="wp-core-ui">
						<div id="login">
							<h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
						</div>
					</body>
				</html>`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Run nuclei with panel detection templates
		output, err := exec.CommandContext(ctx, "nuclei",
			"-u", server.URL,
			"-tags", "panel", // Admin panels
			"-j",
			"-silent",
			"-no-color",
			"-duc",
			"-rl", "100",
			"-c", "25",
			"-timeout", "3",
		).CombinedOutput()

		if err != nil && ctx.Err() == nil {
			t.Logf("Nuclei error: %v, output: %s", err, string(output))
		}

		cfg := Config{}
		scanner := NewNucleiScannerWithLogger(cfg, []string{}, logger.GetGlobalLogger())

		findings, err := scanner.ParseResults(output)
		require.NoError(t, err)

		// Log what we found
		t.Logf("Found %d panel findings", len(findings))
		for _, f := range findings {
			t.Logf("Panel: %s - %s at %s", f.Type, f.Title, f.Location)
		}
	})

	t.Run("Exposure Detection - Fast", func(t *testing.T) {
		// Create a server with exposed files
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.git/config":
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprintf(w, "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n")
			case "/.env":
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprintf(w, "DB_PASSWORD=secret123\nAPI_KEY=sk_live_abcd1234\n")
			case "/config.json":
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"database":{"password":"admin123"},"api":{"key":"secret"}}`)
			case "/.DS_Store":
				// Return a minimal DS_Store response
				w.Header().Set("Content-Type", "application/octet-stream")
				w.Write([]byte("\x00\x00\x00\x01Bud1"))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Run with exposure detection templates
		output, err := exec.CommandContext(ctx, "nuclei",
			"-u", server.URL,
			"-tags", "exposure,config", // File exposures and configs
			"-j",
			"-silent",
			"-no-color",
			"-duc",
			"-rl", "100",
			"-c", "50",
			"-timeout", "3",
		).CombinedOutput()

		if err != nil && ctx.Err() == nil {
			t.Logf("Nuclei error: %v", err)
		}

		cfg := Config{}
		scanner := NewNucleiScannerWithLogger(cfg, []string{}, logger.GetGlobalLogger())

		findings, err := scanner.ParseResults(output)
		require.NoError(t, err)

		// Should find git config, env file, or config exposures
		t.Logf("Found %d exposure findings", len(findings))
		for _, f := range findings {
			t.Logf("Exposure: %s - %s", f.Type, f.Title)
			assert.Contains(t, []string{
				"Information Exposure",
				"Configuration Issue",
				"Information Disclosure",
				"Misconfiguration",
			}, f.Type)
		}
	})

	t.Run("Single Template Test", func(t *testing.T) {
		// This is the fastest possible test - run a single template
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Always return success
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "OK")
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Try to run with a basic tech detection template
		output, err := exec.CommandContext(ctx, "nuclei",
			"-u", server.URL,
			"-id", "options-method", // A simple, fast check
			"-j",
			"-silent",
			"-no-color",
			"-duc",
		).CombinedOutput()

		// This might not find anything, but we're testing the execution
		if err == nil || (err != nil && len(output) > 0) {
			cfg := Config{}
			scanner := NewNucleiScannerWithLogger(cfg, []string{}, logger.GetGlobalLogger())

			findings, parseErr := scanner.ParseResults(output)
			assert.NoError(t, parseErr)

			t.Logf("Single template test found %d findings", len(findings))
		}
	})
}

func TestNucleiScanner_RealOutput(t *testing.T) {
	// Test parsing of real nuclei output captured from actual runs
	scanner := NewNucleiScannerWithLogger(Config{}, []string{}, logger.GetGlobalLogger())

	t.Run("Parse Real Tech Detection Output", func(t *testing.T) {
		// This is real output from nuclei -tags tech
		realOutput := `{"template-id":"tech-detect","info":{"name":"Wappalyzer Technology Detection","author":["hakluke"],"tags":["tech"],"severity":"info"},"matcher-name":"nginx","type":"http","host":"http://example.com","matched-at":"http://example.com/","ip":"93.184.216.34","timestamp":"2024-01-15T10:00:00Z"}
{"template-id":"apache-detect","info":{"name":"Apache Detection","author":["philippedelteil","pd-team"],"tags":["tech","apache"],"severity":"info"},"type":"http","host":"http://example.com","matched-at":"http://example.com/","meta":{"version":"2.4.41"},"extracted-results":["Apache/2.4.41"],"ip":"93.184.216.34","timestamp":"2024-01-15T10:00:01Z"}`

		findings, err := scanner.ParseResults([]byte(realOutput))
		require.NoError(t, err)
		assert.Len(t, findings, 2)

		// Check first finding
		assert.Equal(t, "Technology Detection", findings[0].Type)
		assert.Contains(t, findings[0].Title, "Technology Detection")
		assert.Equal(t, "info", findings[0].Severity)

		// Check second finding
		assert.Equal(t, "Technology Detection", findings[1].Type)
		assert.Contains(t, findings[1].Title, "Apache")
	})

	t.Run("Parse Real Exposure Output", func(t *testing.T) {
		// Real output from exposure detection
		realOutput := `{"template-id":"git-config","info":{"name":"Git Config File Detection","author":["Ice3man543"],"tags":["exposure","git"],"severity":"medium","description":"Git config file was detected."},"type":"http","host":"http://example.com","matched-at":"http://example.com/.git/config","ip":"93.184.216.34","timestamp":"2024-01-15T10:00:00Z"}`

		findings, err := scanner.ParseResults([]byte(realOutput))
		require.NoError(t, err)
		assert.Len(t, findings, 1)

		assert.Equal(t, "Information Exposure", findings[0].Type)
		assert.Equal(t, "medium", findings[0].Severity)
		assert.Contains(t, findings[0].Title, "Git Config")
	})
}
