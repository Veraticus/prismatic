package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/joshsymonds/prismatic/pkg/logger"
)

// GitleaksScanner implements secret detection in git repositories.
type GitleaksScanner struct {
	*BaseScanner
	repoPaths  map[string]string
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
		repoPaths:   nil,
	}
}

// NewGitleaksScannerWithRepositories creates a new Gitleaks scanner for multiple repositories.
func NewGitleaksScannerWithRepositories(config Config, repoPaths map[string]string, log logger.Logger) *GitleaksScanner {
	return &GitleaksScanner{
		BaseScanner: NewBaseScannerWithLogger("gitleaks", config, log),
		targetPath:  "",
		repoPaths:   repoPaths,
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

	// Determine which scan mode to use
	switch {
	case len(s.repoPaths) > 0:
		// Multiple repositories mode
		s.logger.Info("Gitleaks: Scanning repositories", "count", len(s.repoPaths))
		allFindings := []models.Finding{}

		for repoName, repoPath := range s.repoPaths {
			s.logger.Debug("Scanning repository", "name", repoName, "path", repoPath)

			// Update target path for this repository
			s.targetPath = repoPath

			// Run Gitleaks on this repository
			output, err := s.runGitleaks(ctx)
			s.logger.Debug("Gitleaks output", "repo", repoName, "output_len", len(output), "err", err)
			if err != nil {
				// Gitleaks returns exit code 1 when secrets are found
				// Only treat it as an error if it's not an exit error
				if _, ok := err.(*exec.ExitError); !ok {
					s.logger.Error("Failed to scan repository", "repo", repoName, "error", err)
					continue
				}
			}

			// Parse results
			findings, parseErr := s.ParseResults(output)
			if parseErr != nil {
				s.logger.Error("Failed to parse results", "repo", repoName, "error", parseErr)
				continue
			}

			s.logger.Debug("Parsed findings", "repo", repoName, "count", len(findings))

			// Add repository context to findings
			for i := range findings {
				findings[i].Metadata["repository"] = repoName
				// Update resource to include repository name
				findings[i].Resource = fmt.Sprintf("%s:%s", repoName, findings[i].Resource)
			}

			allFindings = append(allFindings, findings...)
		}

		result.Findings = allFindings
		s.logger.Debug("Total findings collected", "count", len(allFindings))
	case s.targetPath != "":
		// Single target scanning
		s.logger.Info("Gitleaks: Scanning single target", "path", s.targetPath)
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
	default:
		// No repositories or targets configured
		s.logger.Info("Gitleaks: No repositories configured, skipping scan")
		result.EndTime = time.Now()
		return result, ErrNoTargets
	}

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
		return nil, fmt.Errorf("gitleaks: failed to parse JSON output: %w", err)
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
		).WithSeverity(models.SeverityCritical) // All secrets are critical
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
		finding.Metadata = map[string]string{
			"rule_id":     leak.RuleID,
			"description": leak.Description,
			"secret":      leak.Match,
			"commit":      leak.Commit,
			"author":      leak.Author,
			"email":       leak.Email,
			"fingerprint": leak.Fingerprint,
			"entropy":     fmt.Sprintf("%.2f", leak.Entropy),
		}

		if leak.StartLine > 0 {
			finding.Metadata["start_line"] = fmt.Sprintf("%d", leak.StartLine)
			finding.Metadata["end_line"] = fmt.Sprintf("%d", leak.EndLine)
			finding.Metadata["start_column"] = fmt.Sprintf("%d", leak.StartColumn)
			finding.Metadata["end_column"] = fmt.Sprintf("%d", leak.EndColumn)
		}

		findings = append(findings, *finding)
	}

	return findings, nil
}

// runGitleaks executes the gitleaks command.
func (s *GitleaksScanner) runGitleaks(ctx context.Context) ([]byte, error) {
	// Create a temporary file for the JSON report
	reportFile, err := os.CreateTemp("", "gitleaks-report-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	reportPath := reportFile.Name()
	if closeErr := reportFile.Close(); closeErr != nil {
		return nil, fmt.Errorf("gitleaks: failed to close report file: %w", closeErr)
	}
	defer func() {
		_ = os.Remove(reportPath)
	}()

	// Use 'git' command for git repositories
	args := []string{
		"git",
		".",
		"--report-path", reportPath,
		"--exit-code", "0", // Don't exit with error when secrets found
	}

	// Add config file if exists
	configPath := filepath.Join(s.config.WorkingDir, ".gitleaks.toml")
	if _, lookupErr := exec.LookPath(configPath); lookupErr == nil {
		args = append(args, "--config", configPath)
	}

	// Run command with the target path as working directory
	cmd := exec.CommandContext(ctx, "gitleaks", args...)
	cmd.Dir = s.targetPath

	s.logger.Debug("Running gitleaks command", "cmd", "gitleaks", "args", args, "dir", s.targetPath)

	// Set environment if provided
	if s.config.Env != nil {
		env := os.Environ()
		for k, v := range s.config.Env {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
		cmd.Env = env
	}

	output, err := cmd.CombinedOutput()

	// Gitleaks returns exit code 1 when secrets are found
	ok, realErr := HandleNonZeroExit(err, 1)
	if !ok {
		return nil, fmt.Errorf("gitleaks failed: %w, output: %s", realErr, string(output))
	}

	// Read the JSON report
	jsonOutput, readErr := os.ReadFile(reportPath) // #nosec G304 - reportPath is internally generated tempfile
	if readErr != nil {
		return nil, fmt.Errorf("failed to read report file: %w", readErr)
	}

	return jsonOutput, nil
}

// getVersion returns the Gitleaks version.
func (s *GitleaksScanner) getVersion(ctx context.Context) string {
	return GetScannerVersion(ctx, "gitleaks", "version", func(output []byte) string {
		// Parse version from output like "v8.18.0"
		version := strings.TrimSpace(string(output))
		if strings.HasPrefix(version, "v") {
			return version[1:]
		}
		return version
	})
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
