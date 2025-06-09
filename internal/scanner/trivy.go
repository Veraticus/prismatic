package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/Veraticus/prismatic/internal/models"
	"github.com/Veraticus/prismatic/pkg/logger"
)

// TrivyScanner implements container and image vulnerability scanning.
type TrivyScanner struct {
	*BaseScanner
	executor *ScannerExecutor
	targets  []string
}

// NewTrivyScanner creates a new Trivy scanner instance.
func NewTrivyScanner(config Config, targets []string) *TrivyScanner {
	return NewTrivyScannerWithLogger(config, targets, logger.GetGlobalLogger())
}

// NewTrivyScannerWithLogger creates a new Trivy scanner instance with a custom logger.
func NewTrivyScannerWithLogger(config Config, targets []string, log logger.Logger) *TrivyScanner {
	return &TrivyScanner{
		BaseScanner: NewBaseScannerWithLogger("trivy", config, log),
		targets:     targets,
		executor:    NewScannerExecutor(5 * time.Minute),
	}
}

// Scan executes Trivy against configured targets.
func (s *TrivyScanner) Scan(ctx context.Context) (*models.ScanResult, error) {
	return s.executor.Execute(ctx, s, func(scanCtx context.Context) (*models.ScanResult, error) {
		result := &models.ScanResult{
			Scanner:   s.Name(),
			Version:   s.getVersion(scanCtx),
			StartTime: time.Now(),
			Findings:  []models.Finding{},
		}

		// Use MultiTargetExecutor for processing multiple targets
		mte := &MultiTargetExecutor{
			Scanner:   s.Name(),
			ParseFunc: s.ParseResults,
		}

		mte.ProcessTargets(s.targets, func(target string) ([]byte, error) {
			return s.scanTarget(scanCtx, target)
		}, result)

		return result, nil
	})
}

// ParseResults converts Trivy JSON output to normalized findings.
func (s *TrivyScanner) ParseResults(raw []byte) ([]models.Finding, error) {
	var report TrivyReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, NewStructuredError(s.Name(), ErrorTypeParse, err)
	}

	var findings []models.Finding

	// Process each result (target)
	for _, result := range report.Results {
		target := result.Target
		if target == "" && report.ArtifactName != "" {
			target = report.ArtifactName
		}

		// Process vulnerabilities
		for _, vuln := range result.Vulnerabilities {
			finding := models.NewFinding(
				s.Name(),
				"vulnerability",
				target,
				vuln.PkgName,
			).WithSeverity(vuln.Severity)
			finding.Title = fmt.Sprintf("%s: %s vulnerability in %s",
				vuln.VulnerabilityID, vuln.Severity, vuln.PkgName)
			finding.Description = vuln.Description
			if finding.Description == "" {
				finding.Description = fmt.Sprintf(
					"Package %s version %s is vulnerable to %s",
					vuln.PkgName, vuln.InstalledVersion, vuln.VulnerabilityID,
				)
			}

			// Build remediation
			if vuln.FixedVersion != "" {
				finding.Remediation = fmt.Sprintf("Update %s to version %s or later",
					vuln.PkgName, vuln.FixedVersion)
			} else {
				finding.Remediation = fmt.Sprintf("No fix available yet for %s in %s",
					vuln.VulnerabilityID, vuln.PkgName)
			}

			// Add references
			if vuln.PrimaryURL != "" {
				finding.References = []string{vuln.PrimaryURL}
			}
			finding.References = append(finding.References, vuln.References...)

			// Parse and set published date for CVEs
			if vuln.PublishedDate != "" {
				if pubDate, err := time.Parse(time.RFC3339, vuln.PublishedDate); err == nil {
					finding.PublishedDate = pubDate
				} else if pubDate, err := time.Parse("2006-01-02T15:04:05Z", vuln.PublishedDate); err == nil {
					finding.PublishedDate = pubDate
				}
			}

			// Add metadata
			finding.Metadata["installed_version"] = vuln.InstalledVersion
			finding.Metadata["fixed_version"] = vuln.FixedVersion
			finding.Metadata["pkg_type"] = result.Type
			if vuln.CVSS != nil {
				finding.Metadata["cvss_score"] = fmt.Sprintf("%v", vuln.CVSS)
			}
			if vuln.PublishedDate != "" {
				finding.Metadata["published_date"] = vuln.PublishedDate
			}
			if vuln.LastModifiedDate != "" {
				finding.Metadata["last_modified_date"] = vuln.LastModifiedDate
			}

			findings = append(findings, *finding)
		}

		// Process misconfigurations
		for _, misconf := range result.Misconfigurations {
			finding := models.NewFinding(
				s.Name(),
				"misconfiguration",
				target,
				fmt.Sprintf("%s:%d", result.Target, misconf.StartLine),
			).WithSeverity(misconf.Severity)
			finding.Title = misconf.Title
			finding.Description = misconf.Description
			finding.Remediation = misconf.Resolution
			finding.Impact = misconf.Message

			if misconf.PrimaryURL != "" {
				finding.References = []string{misconf.PrimaryURL}
			}

			finding.Metadata["check_id"] = misconf.ID
			finding.Metadata["check_type"] = misconf.Type
			finding.Metadata["start_line"] = fmt.Sprintf("%d", misconf.StartLine)
			finding.Metadata["end_line"] = fmt.Sprintf("%d", misconf.EndLine)

			findings = append(findings, *finding)
		}

		// Process secrets
		for _, secret := range result.Secrets {
			finding := models.NewFinding(
				s.Name(),
				"secret",
				target,
				fmt.Sprintf("%s:%d", secret.Target, secret.StartLine),
			).WithSeverity(secret.Severity)
			finding.Title = fmt.Sprintf("Exposed %s", secret.Title)
			finding.Description = fmt.Sprintf("Found %s at line %d", secret.Title, secret.StartLine)
			finding.Remediation = "Remove the secret from the codebase and rotate it immediately"
			finding.Impact = "Exposed secrets can lead to unauthorized access and data breaches"

			finding.Metadata["rule_id"] = secret.RuleID
			finding.Metadata["match"] = secret.Match
			finding.Metadata["start_line"] = fmt.Sprintf("%d", secret.StartLine)
			finding.Metadata["end_line"] = fmt.Sprintf("%d", secret.EndLine)

			findings = append(findings, *finding)
		}
	}

	return findings, nil
}

// scanTarget runs Trivy against a single target.
func (s *TrivyScanner) scanTarget(ctx context.Context, target string) ([]byte, error) {
	args := []string{
		"--format", "json",
		"--quiet",
	}

	// Determine scan type based on target
	switch {
	case strings.Contains(target, ":") || strings.Contains(target, "/"):
		// Image scan
		args = append(args, "image", target)
	case strings.HasSuffix(target, ".tar"):
		// Archive scan
		args = append(args, "image", "--input", target)
	default:
		// Filesystem/repo scan
		args = append(args, "fs", target)
	}

	cmd := exec.CommandContext(ctx, "trivy", args...)
	// Only set working directory if it's not the scan output directory
	if s.config.WorkingDir != "" && !strings.Contains(s.config.WorkingDir, "data/scans") {
		cmd.Dir = s.config.WorkingDir
	}
	// Convert env map to slice of strings
	if s.config.Env != nil {
		for k, v := range s.config.Env {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
		}
	}

	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("trivy failed: %s", string(exitErr.Stderr))
		}
		return nil, err
	}

	return output, nil
}

// getVersion returns the Trivy version.
func (s *TrivyScanner) getVersion(ctx context.Context) string {
	cmd := exec.CommandContext(ctx, "trivy", "--version")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}

	// Parse version from output like "Version: 0.45.0"
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Version:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		}
	}

	return "unknown"
}

// TrivyReport represents the Trivy JSON output structure.
type TrivyReport struct {
	ArtifactName string        `json:"ArtifactName"`
	ArtifactType string        `json:"ArtifactType"`
	Results      []TrivyResult `json:"Results"`
}

// TrivyResult represents a single result from a Trivy scan.
type TrivyResult struct {
	Target            string                  `json:"Target"`
	Type              string                  `json:"Type"`
	Vulnerabilities   []TrivyVulnerability    `json:"Vulnerabilities"`
	Misconfigurations []TrivyMisconfiguration `json:"Misconfigurations"`
	Secrets           []TrivySecret           `json:"Secrets"`
}

// TrivyVulnerability represents a vulnerability found by Trivy.
type TrivyVulnerability struct {
	CVSS             map[string]any `json:"CVSS"`
	VulnerabilityID  string         `json:"VulnerabilityID"`
	PkgName          string         `json:"PkgName"`
	InstalledVersion string         `json:"InstalledVersion"`
	FixedVersion     string         `json:"FixedVersion"`
	Severity         string         `json:"Severity"`
	Description      string         `json:"Description"`
	PrimaryURL       string         `json:"PrimaryURL"`
	PublishedDate    string         `json:"PublishedDate"`
	LastModifiedDate string         `json:"LastModifiedDate"`
	References       []string       `json:"References"`
}

// TrivyMisconfiguration represents a misconfiguration found by Trivy.
type TrivyMisconfiguration struct {
	Type        string `json:"Type"`
	ID          string `json:"ID"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
	Message     string `json:"Message"`
	Resolution  string `json:"Resolution"`
	Severity    string `json:"Severity"`
	PrimaryURL  string `json:"PrimaryURL"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
}

// TrivySecret represents a secret found by Trivy.
type TrivySecret struct {
	RuleID    string `json:"RuleID"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	Target    string `json:"Target"`
	Match     string `json:"Match"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
}
