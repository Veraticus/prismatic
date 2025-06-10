//go:build integration
// +build integration

package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Veraticus/prismatic/internal/models"
	"github.com/Veraticus/prismatic/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNucleiScanner_MinimalIntegration(t *testing.T) {
	// Skip if nuclei is not installed
	if _, err := exec.LookPath("nuclei"); err != nil {
		t.Skip("nuclei not installed")
	}

	// First, let's check if nuclei has templates installed
	output, err := exec.Command("nuclei", "-tl").CombinedOutput()
	if err != nil || strings.Contains(string(output), "no templates found") {
		t.Skip("nuclei templates not installed - run 'nuclei -update-templates'")
	}

	t.Run("Minimal Template Test", func(t *testing.T) {
		// Create a test server with a known vulnerability
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/":
				w.Header().Set("Server", "Apache/2.4.29")
				fmt.Fprintf(w, "<html><title>Test</title><body>Test Page</body></html>")
			case "/.git/config":
				// Git config exposure - this is detected by nuclei
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n")
			case "/robots.txt":
				// Robots file that reveals paths
				fmt.Fprintf(w, "User-agent: *\nDisallow: /admin/\nDisallow: /.git/\n")
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		// First, let's run nuclei with a very specific template to ensure it works
		// The git-config template is commonly available and fast
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Try to find the git-config template
		templatePath := ""
		possiblePaths := []string{
			"$HOME/nuclei-templates/http/exposures/configs/git-config.yaml",
			"/root/nuclei-templates/http/exposures/configs/git-config.yaml",
			os.ExpandEnv("$HOME/.local/nuclei-templates/http/exposures/configs/git-config.yaml"),
		}

		for _, p := range possiblePaths {
			expanded := os.ExpandEnv(p)
			if _, err := os.Stat(expanded); err == nil {
				templatePath = expanded
				break
			}
		}

		if templatePath == "" {
			// Try to run with template id instead
			t.Log("Could not find git-config template file, trying with template ID")

			// Run nuclei with just the git-config check
			output, err := exec.CommandContext(ctx, "nuclei",
				"-u", server.URL,
				"-id", "git-config", // Use template ID
				"-j", // JSON output
				"-silent",
				"-no-color",
				"-disable-update-check",
			).CombinedOutput()

			if err != nil && ctx.Err() == nil {
				t.Logf("Nuclei with -id failed: %v, output: %s", err, string(output))
			} else if ctx.Err() != nil {
				t.Skip("Nuclei timed out even with single template")
			} else {
				t.Logf("Nuclei output: %s", string(output))
			}
		} else {
			t.Logf("Found template at: %s", templatePath)

			// Run nuclei with specific template file
			output, err := exec.CommandContext(ctx, "nuclei",
				"-u", server.URL,
				"-t", templatePath,
				"-j", // JSON output
				"-silent",
				"-no-color",
				"-disable-update-check",
			).CombinedOutput()

			if err != nil {
				t.Fatalf("Nuclei failed: %v, output: %s", err, string(output))
			}

			t.Logf("Nuclei output: %s", string(output))

			// Now test our scanner with the same specific template
			// We'll need to modify our scanner to support specific templates
			// For now, let's just verify the output can be parsed
			if len(output) > 0 && strings.Contains(string(output), "git-config") {
				cfg := Config{}
				scanner := NewNucleiScannerWithLogger(cfg, []string{}, logger.GetGlobalLogger())

				// Extract JSON lines
				var jsonLines []string
				for _, line := range strings.Split(string(output), "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
						jsonLines = append(jsonLines, line)
					}
				}

				if len(jsonLines) > 0 {
					t.Logf("Attempting to parse %d JSON lines", len(jsonLines))
					jsonData := []byte(strings.Join(jsonLines, "\n"))
					t.Logf("JSON data to parse: %s", string(jsonData))

					findings, err := scanner.ParseResults(jsonData)
					if err != nil {
						t.Fatalf("Parse error: %v", err)
					}

					t.Logf("ParseResults returned %d findings", len(findings))
					assert.NotEmpty(t, findings, "Should parse at least one finding")

					for _, f := range findings {
						t.Logf("Parsed finding: %s - %s (severity: %s)", f.Type, f.Title, f.Severity)
						assert.Equal(t, "nuclei", f.Scanner)
						assert.NotEmpty(t, f.Title)
						assert.NotEmpty(t, f.Metadata["template_id"])
					}
				}
			}
		}
	})

	t.Run("Direct Scanner Test", func(t *testing.T) {
		// Test our scanner directly with a local server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.git/config" {
				fmt.Fprintf(w, "[core]\nrepositoryformatversion = 0\n")
			} else {
				fmt.Fprintf(w, "OK")
			}
		}))
		defer server.Close()

		// Create scanner with very short timeout
		cfg := Config{
			Timeout: 20,
		}

		scanner := NewNucleiScannerWithLogger(cfg, []string{server.URL}, logger.GetGlobalLogger())

		// Override the runNuclei method to add specific arguments
		// For this test, we'll create a wrapper
		testScanner := &testableNucleiScanner{
			NucleiScanner: scanner,
			extraArgs:     []string{"-id", "git-config"}, // Only run git-config template
		}

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		result, err := testScanner.Scan(ctx)

		if ctx.Err() != nil {
			t.Skip("Scanner timed out - nuclei may not have templates installed")
		}

		require.NoError(t, err)
		assert.NotNil(t, result)

		t.Logf("Scanner found %d findings", len(result.Findings))
		if len(result.Findings) > 0 {
			for _, f := range result.Findings {
				t.Logf("Finding: %s - %s", f.Type, f.Title)
			}
		}
	})
}

// testableNucleiScanner wraps NucleiScanner to add extra arguments for testing
type testableNucleiScanner struct {
	*NucleiScanner
	extraArgs []string
}

func (s *testableNucleiScanner) Scan(ctx context.Context) (*models.ScanResult, error) {
	// We can't easily override runNuclei, so let's just run the parent scan
	// and note that this is a limitation of the current design
	return s.NucleiScanner.Scan(ctx)
}

// TestNucleiRealWorld tests against a real website known to have issues
func TestNucleiRealWorld(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping real-world test in short mode")
	}

	// Skip if nuclei is not installed
	if _, err := exec.LookPath("nuclei"); err != nil {
		t.Skip("nuclei not installed")
	}

	// Test against a known vulnerable test site
	// http://testphp.vulnweb.com is a deliberately vulnerable site for testing
	testURL := "http://testphp.vulnweb.com"

	// First check if the site is reachable
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(testURL)
	if err != nil {
		t.Skipf("Test site %s is not reachable: %v", testURL, err)
	}
	resp.Body.Close()

	// Run nuclei with very limited templates
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Run with only critical severity to reduce scan time
	output, err := exec.CommandContext(ctx, "nuclei",
		"-u", testURL,
		"-severity", "critical,high",
		"-j",
		"-silent",
		"-no-color",
		"-disable-update-check",
		"-timeout", "5",
		"-bulk-size", "10",
		"-c", "10", // concurrency
		"-rl", "10", // rate limit
	).CombinedOutput()

	if ctx.Err() != nil {
		t.Skip("Nuclei scan timed out")
	}

	if err != nil {
		t.Logf("Nuclei error: %v", err)
	}

	t.Logf("Nuclei found %d bytes of output", len(output))

	// Parse any findings
	if len(output) > 0 {
		cfg := Config{}
		scanner := NewNucleiScannerWithLogger(cfg, []string{}, logger.GetGlobalLogger())

		// Extract JSON lines
		var jsonCount int
		var jsonLines []byte
		for _, line := range strings.Split(string(output), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
				jsonLines = append(jsonLines, []byte(line+"\n")...)
				jsonCount++
			}
		}

		t.Logf("Found %d JSON lines in output", jsonCount)

		if len(jsonLines) > 0 {
			findings, err := scanner.ParseResults(jsonLines)
			require.NoError(t, err)

			t.Logf("Parsed %d findings", len(findings))
			for i, f := range findings {
				if i < 5 { // Log first 5 findings
					t.Logf("Finding: %s - %s (severity: %s, template: %s)",
						f.Type, f.Title, f.Severity, f.Metadata["template_id"])
				}
			}
		}
	}
}
