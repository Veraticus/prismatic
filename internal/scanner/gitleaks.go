package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Veraticus/prismatic/internal/models"
	"github.com/Veraticus/prismatic/pkg/logger"
)

// GitleaksScanner implements secret detection in git repositories.
type GitleaksScanner struct {
	*BaseScanner
	targetPath string
}

// NewGitleaksScanner creates a new Gitleaks scanner instance.
func NewGitleaksScanner(config Config, targetPath string) *GitleaksScanner {
	return NewGitleaksScannerWithLogger(config, targetPath, logger.GetGlobalLogger())
}

// NewGitleaksScannerWithLogger creates a new Gitleaks scanner instance with a custom logger.
func NewGitleaksScannerWithLogger(config Config, targetPath string, log logger.Logger) *GitleaksScanner {
	if targetPath == "" {
		targetPath = "."
	}
	return &GitleaksScanner{
		BaseScanner: NewBaseScannerWithLogger("gitleaks", config, log),
		targetPath:  targetPath,
	}
}

// Scan executes Gitleaks against the target repository.
func (s *GitleaksScanner) Scan(ctx context.Context) (*models.ScanResult, error) {
	startTime := time.Now()

	result := &models.ScanResult{
		Scanner:   s.Name(),
		Version:   s.getVersion(ctx),
		StartTime: startTime,
		Findings:  []models.Finding{},
	}

	// Run Gitleaks
	output, err := s.runGitleaks(ctx)
	if err != nil {
		// Gitleaks returns exit code 1 when secrets are found
		// Only treat it as an error if it's not an exit error
		if _, ok := err.(*exec.ExitError); !ok {
			result.EndTime = time.Now()
			result.Error = fmt.Sprintf("gitleaks scan failed: %v", err)
			return result, nil
		}
	}

	// Parse results
	findings, parseErr := s.ParseResults(output)
	if parseErr != nil {
		result.EndTime = time.Now()
		result.Error = fmt.Sprintf("failed to parse results: %v", parseErr)
		return result, nil
	}

	result.Findings = findings
	result.EndTime = time.Now()
	return result, nil
}

// ParseResults converts Gitleaks JSON output to normalized findings.
func (s *GitleaksScanner) ParseResults(raw []byte) ([]models.Finding, error) {
	// Handle empty results
	if len(raw) == 0 || string(raw) == "" {
		return []models.Finding{}, nil
	}

	var leaks []GitleaksLeak
	if err := json.Unmarshal(raw, &leaks); err != nil {
		return nil, NewScannerError(s.Name(), "parse", err)
	}

	findings := make([]models.Finding, 0, len(leaks))

	for _, leak := range leaks {
		location := leak.File
		if leak.StartLine > 0 {
			location = fmt.Sprintf("%s:%d", leak.File, leak.StartLine)
		}

		finding := models.NewFinding(
			s.Name(),
			"secret",
			leak.File,
			location,
		)

		finding.Severity = models.SeverityCritical // All secrets are critical
		finding.Title = fmt.Sprintf("Exposed %s", leak.Description)

		// Build description
		finding.Description = fmt.Sprintf("Found %s in %s", leak.Description, leak.File)
		if leak.StartLine > 0 {
			finding.Description += fmt.Sprintf(" at line %d", leak.StartLine)
		}
		if leak.Author != "" {
			finding.Description += fmt.Sprintf(" (committed by %s)", leak.Author)
		}

		finding.Remediation = "Remove the secret from the repository history and rotate it immediately"
		finding.Impact = "Exposed secrets can lead to unauthorized access, data breaches, and compromise of connected systems"

		// Add references
		if leak.RuleID != "" {
			finding.References = []string{
				fmt.Sprintf("https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml#%s", leak.RuleID),
			}
		}

		// Parse commit date if available
		if leak.Date != "" {
			// Try common git date formats
			for _, format := range []string{
				time.RFC3339,
				"2006-01-02T15:04:05Z",
				"2006-01-02 15:04:05 -0700",
				"Mon Jan 2 15:04:05 2006 -0700",
			} {
				if commitDate, err := time.Parse(format, leak.Date); err == nil {
					finding.DiscoveredDate = commitDate
					break
				}
			}
		}

		// Add metadata
		finding.Metadata["rule_id"] = leak.RuleID
		finding.Metadata["commit"] = leak.Commit
		finding.Metadata["author"] = leak.Author
		finding.Metadata["email"] = leak.Email
		finding.Metadata["date"] = leak.Date
		finding.Metadata["file"] = leak.File
		if leak.StartLine > 0 {
			finding.Metadata["start_line"] = fmt.Sprintf("%d", leak.StartLine)
			finding.Metadata["end_line"] = fmt.Sprintf("%d", leak.EndLine)
			finding.Metadata["start_column"] = fmt.Sprintf("%d", leak.StartColumn)
			finding.Metadata["end_column"] = fmt.Sprintf("%d", leak.EndColumn)
		}
		if leak.Match != "" {
			// Redact the actual secret value for security
			finding.Metadata["match_pattern"] = s.redactSecret(leak.Match)
		}

		findings = append(findings, *finding)
	}

	return findings, nil
}

// runGitleaks executes the gitleaks command.
func (s *GitleaksScanner) runGitleaks(ctx context.Context) ([]byte, error) {
	args := []string{
		"detect",
		"--report-format", "json",
		"--exit-code", "0", // Don't exit with error when secrets found
		"--source", s.targetPath,
	}

	// Add config file if exists
	configPath := filepath.Join(s.config.WorkingDir, ".gitleaks.toml")
	if _, err := exec.LookPath(configPath); err == nil {
		args = append(args, "--config", configPath)
	}

	cmd := exec.CommandContext(ctx, "gitleaks", args...)
	cmd.Dir = s.config.WorkingDir

	// Convert env map to slice of strings
	if s.config.Env != nil {
		for k, v := range s.config.Env {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
		}
	}

	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Check if there's stderr output
			if len(exitErr.Stderr) > 0 {
				return nil, fmt.Errorf("gitleaks failed: %s", string(exitErr.Stderr))
			}
			// Exit code 1 means secrets were found, which is expected
			// Return the output for parsing
			return output, nil
		}
		return nil, err
	}

	return output, nil
}

// getVersion returns the Gitleaks version.
func (s *GitleaksScanner) getVersion(ctx context.Context) string {
	cmd := exec.CommandContext(ctx, "gitleaks", "version")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}

	// Parse version from output like "v8.18.0"
	version := strings.TrimSpace(string(output))
	if strings.HasPrefix(version, "v") {
		return version[1:]
	}
	return version
}

// redactSecret partially redacts a secret for security.
func (s *GitleaksScanner) redactSecret(secret string) string {
	if len(secret) <= 8 {
		return "***REDACTED***"
	}

	// Show first 4 and last 4 characters
	return fmt.Sprintf("%s...%s", secret[:4], secret[len(secret)-4:])
}

// GitleaksLeak represents a single leak finding from Gitleaks.
type GitleaksLeak struct {
	Email       string   `json:"Email"`
	Date        string   `json:"Date"`
	Fingerprint string   `json:"Fingerprint"`
	RuleID      string   `json:"RuleID"`
	Message     string   `json:"Message"`
	Match       string   `json:"Match"`
	Secret      string   `json:"Secret"`
	File        string   `json:"File"`
	SymlinkFile string   `json:"SymlinkFile"`
	Description string   `json:"Description"`
	Commit      string   `json:"Commit"`
	Author      string   `json:"Author"`
	Tags        []string `json:"Tags"`
	Entropy     float64  `json:"Entropy"`
	StartLine   int      `json:"StartLine"`
	EndColumn   int      `json:"EndColumn"`
	StartColumn int      `json:"StartColumn"`
	EndLine     int      `json:"EndLine"`
}
