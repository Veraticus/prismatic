// Package scanner provides security scanner implementations for Prismatic.
package scanner

import (
	"bytes"
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

// CheckovScanner implements Infrastructure-as-Code security scanning.
type CheckovScanner struct {
	*BaseScanner
	targets []string
}

// NewCheckovScanner creates a new Checkov scanner instance.
func NewCheckovScanner(config Config, targets []string) *CheckovScanner {
	return NewCheckovScannerWithLogger(config, targets, logger.GetGlobalLogger())
}

// NewCheckovScannerWithLogger creates a new Checkov scanner instance with a custom logger.
func NewCheckovScannerWithLogger(config Config, targets []string, log logger.Logger) *CheckovScanner {
	return &CheckovScanner{
		BaseScanner: NewBaseScannerWithLogger("checkov", config, log),
		targets:     targets,
	}
}

// Scan executes Checkov against configured targets.
func (s *CheckovScanner) Scan(ctx context.Context) (*models.ScanResult, error) {
	startTime := time.Now()

	result := &models.ScanResult{
		Scanner:   s.Name(),
		Version:   s.getVersion(ctx),
		StartTime: startTime,
		Findings:  []models.Finding{},
	}

	if len(s.targets) == 0 {
		s.logger.Info("Checkov: No targets configured, skipping scan")
		result.EndTime = time.Now()
		return result, ErrNoTargets
	}

	s.logger.Info("Checkov: Scanning targets", "count", len(s.targets), "targets", s.targets)

	// Scan each target directory
	for _, target := range s.targets {
		if err := ctx.Err(); err != nil {
			result.EndTime = time.Now()
			result.Error = fmt.Sprintf("scan canceled: %v", err)
			return result, nil
		}

		output, err := s.scanTarget(ctx, target)
		if err != nil {
			// Log error but continue with other targets
			if s.config.Debug {
				s.logger.Warn("Checkov scan failed", "target", target, "error", err)
			}
			continue
		}

		findings, err := s.ParseResults(output)
		if err != nil {
			if s.config.Debug {
				s.logger.Warn("Failed to parse Checkov results", "target", target, "error", err, "output_len", len(output))
				// Log first 500 chars of output for debugging
				if len(output) > 0 {
					preview := string(output)
					if len(preview) > 500 {
						preview = preview[:500] + "..."
					}
					s.logger.Debug("Checkov output preview", "preview", preview)
				}
			}
			continue
		}

		if s.config.Debug {
			s.logger.Debug("Successfully parsed findings", "count", len(findings), "target", target)
		}
		result.Findings = append(result.Findings, findings...)
	}

	result.EndTime = time.Now()
	return result, nil
}

// ParseResults converts Checkov JSON output to normalized findings.
func (s *CheckovScanner) ParseResults(raw []byte) ([]models.Finding, error) {
	// Checkov outputs different formats:
	// - Single framework: object with results
	// - Multiple frameworks: array of objects

	// Check if it's an array by looking at the first character
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return []models.Finding{}, nil
	}

	if trimmed[0] == '[' {
		// Handle array format
		var reports []CheckovReport
		if err := json.Unmarshal(raw, &reports); err != nil {
			return nil, fmt.Errorf("checkov: failed to parse results as array: %w", err)
		}

		var findings []models.Finding
		for _, report := range reports {
			reportFindings := s.parseReport(report)
			findings = append(findings, reportFindings...)
		}
		return findings, nil
	}

	// Handle single object format
	var report CheckovReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("checkov: failed to parse results as object: %w", err)
	}

	return s.parseReport(report), nil
}

// parseReport processes a single Checkov report.
func (s *CheckovScanner) parseReport(report CheckovReport) []models.Finding {
	// Pre-calculate total number of failed checks
	totalFailedChecks := len(report.Results.FailedChecks) + len(report.SecretsFailedChecks)

	findings := make([]models.Finding, 0, totalFailedChecks)

	// Process failed checks
	for _, failedCheck := range report.Results.FailedChecks {
		finding := s.createFindingFromCheck(report.CheckType, failedCheck)
		findings = append(findings, *finding)
	}

	// Process secrets findings if present
	for _, secret := range report.SecretsFailedChecks {
		finding := s.createFindingFromSecret(secret)
		findings = append(findings, *finding)
	}

	return findings
}

// createFindingFromCheck creates a normalized finding from a Checkov failed check.
func (s *CheckovScanner) createFindingFromCheck(checkType string, check CheckovFailedCheck) *models.Finding {
	// Handle secrets differently
	if checkType == "secrets" && strings.HasPrefix(check.CheckID, "CKV_SECRET_") {
		// For secrets, the resource is a hash in the Resource field
		location := fmt.Sprintf("line %d", check.FileLineRange[0])

		finding := models.NewFinding(
			s.Name(),
			"exposed-secret",
			check.FilePath,
			location,
		).WithSeverity(check.Severity)
		finding.Title = fmt.Sprintf("Exposed %s", check.CheckName)
		finding.Description = fmt.Sprintf("Found potential %s at line %d in %s",
			check.CheckName, check.FileLineRange[0], check.FilePath)
		finding.Remediation = "Remove the secret from the codebase, rotate it immediately, and use secure secret management"
		finding.Impact = "Exposed secrets can lead to unauthorized access, data breaches, and compromise of connected systems"

		// Add metadata
		finding.Metadata["check_id"] = check.CheckID
		finding.Metadata["check_name"] = check.CheckName
		if len(check.FileLineRange) >= 1 {
			finding.Metadata["line_number"] = fmt.Sprintf("%d", check.FileLineRange[0])
		}
		finding.Metadata["secret_type"] = check.CheckName

		return finding
	}

	// Clean up file path - remove leading slash if present
	filePath := check.FilePath
	if strings.HasPrefix(filePath, "/") && len(filePath) > 1 {
		filePath = filePath[1:]
	}

	// Determine resource path
	resource := filePath
	if check.ResourceAddress != "" {
		resource = fmt.Sprintf("%s:%s", filePath, check.ResourceAddress)
	}

	// Determine location
	location := check.Resource
	if len(check.FileLineRange) >= 2 {
		location = fmt.Sprintf("%s (lines %d-%d)", check.Resource, check.FileLineRange[0], check.FileLineRange[1])
	}

	finding := models.NewFinding(
		s.Name(),
		s.mapCheckIDToType(check.CheckID),
		resource,
		location,
	)

	// Set severity - use default if not provided
	if check.Severity != "" {
		finding = finding.WithSeverity(check.Severity)
	} else {
		// Default severity based on check ID patterns
		switch {
		case strings.Contains(check.CheckID, "_ENCRYPT"):
			finding = finding.WithSeverity("high")
		case strings.HasPrefix(check.CheckID, "CKV_SECRET_"):
			finding = finding.WithSeverity("high")
		case strings.Contains(check.CheckID, "_IAM") || strings.Contains(check.CheckID, "_RBAC"):
			finding = finding.WithSeverity("high")
		case strings.Contains(check.CheckID, "_NETWORK"):
			finding = finding.WithSeverity("medium")
		default:
			finding = finding.WithSeverity("medium")
		}
	}

	finding.Title = check.CheckName
	if finding.Title == "" {
		finding.Title = fmt.Sprintf("%s: %s", check.CheckID, check.CheckName)
	}

	finding.Description = check.Description
	if finding.Description == "" {
		finding.Description = fmt.Sprintf("Check %s failed for resource %s", check.CheckID, check.Resource)
	}

	// Set remediation from guideline or generate default
	if check.Guideline != "" {
		finding.Remediation = fmt.Sprintf("Follow the remediation steps at: %s", check.Guideline)
		finding.References = []string{check.Guideline}
	} else {
		finding.Remediation = fmt.Sprintf("Review and fix the %s configuration to comply with %s",
			check.Resource, check.CheckName)
	}

	// Add metadata
	finding.Metadata["check_id"] = check.CheckID
	finding.Metadata["check_type"] = checkType
	finding.Metadata["check_class"] = check.CheckClass
	finding.Metadata["file_path"] = filePath // Use the cleaned path from above
	finding.Metadata["resource"] = check.Resource

	if check.ResourceAddress != "" {
		finding.Metadata["resource_address"] = check.ResourceAddress
	}

	if len(check.FileLineRange) >= 2 {
		finding.Metadata["start_line"] = fmt.Sprintf("%d", check.FileLineRange[0])
		finding.Metadata["end_line"] = fmt.Sprintf("%d", check.FileLineRange[1])
	}

	if check.CodeBlock != nil {
		switch cb := check.CodeBlock.(type) {
		case string:
			if cb != "" {
				finding.Metadata["code_block"] = cb
			}
		case []any:
			// Handle array format - just store as string representation
			finding.Metadata["code_block"] = fmt.Sprintf("%v", cb)
		}
	}

	return finding
}

// createFindingFromSecret creates a normalized finding from a Checkov secret detection.
func (s *CheckovScanner) createFindingFromSecret(secret CheckovSecretCheck) *models.Finding {
	location := fmt.Sprintf("line %d", secret.LineNumber)

	finding := models.NewFinding(
		s.Name(),
		"exposed-secret",
		secret.FilePath,
		location,
	)

	finding.Severity = models.SeverityHigh // Secrets are always high severity
	finding.Title = fmt.Sprintf("Exposed %s", secret.CheckName)
	finding.Description = fmt.Sprintf("Found potential %s at line %d in %s",
		secret.CheckName, secret.LineNumber, secret.FilePath)
	finding.Remediation = "Remove the secret from the codebase, rotate it immediately, and use secure secret management"
	finding.Impact = "Exposed secrets can lead to unauthorized access, data breaches, and compromise of connected systems"

	// Add metadata
	finding.Metadata["check_id"] = secret.CheckID
	finding.Metadata["check_name"] = secret.CheckName
	finding.Metadata["line_number"] = fmt.Sprintf("%d", secret.LineNumber)
	finding.Metadata["secret_type"] = secret.SecretType

	return finding
}

// mapCheckIDToType maps Checkov check IDs to normalized finding types.
func (s *CheckovScanner) mapCheckIDToType(checkID string) string {
	// Check for specific patterns first before cloud provider prefixes
	switch {
	case strings.HasPrefix(checkID, "CKV_SECRET_"):
		return "exposed-secret"
	case strings.Contains(checkID, "_ENCRYPT") || strings.Contains(checkID, "_ENCRYPTION"):
		return "encryption-misconfiguration"
	case strings.Contains(checkID, "_LOG") || strings.Contains(checkID, "_LOGGING"):
		return "logging-misconfiguration"
	case strings.Contains(checkID, "_IAM") || strings.Contains(checkID, "_RBAC"):
		return "access-control-misconfiguration"
	case strings.Contains(checkID, "_NETWORK") || strings.Contains(checkID, "_NET"):
		return "network-misconfiguration"
	// Check specific known check IDs for better categorization
	case checkID == "CKV_AWS_19" || checkID == "CKV_AWS_21":
		return "encryption-misconfiguration" // S3 encryption checks
	case checkID == "CKV_AWS_40" || checkID == "CKV_AWS_61" || checkID == "CKV_AWS_62":
		return "access-control-misconfiguration" // IAM policy checks
	case checkID == "CKV_AWS_24" || checkID == "CKV_AWS_25":
		return "network-misconfiguration" // Security group checks
	case strings.HasPrefix(checkID, "CKV_AWS_"):
		return "aws-misconfiguration"
	case strings.HasPrefix(checkID, "CKV_AZURE_"):
		return "azure-misconfiguration"
	case strings.HasPrefix(checkID, "CKV_GCP_"):
		return "gcp-misconfiguration"
	case strings.HasPrefix(checkID, "CKV_K8S_"):
		return "kubernetes-misconfiguration"
	case strings.HasPrefix(checkID, "CKV_DOCKER_"):
		return "container-misconfiguration"
	case strings.HasPrefix(checkID, "CKV_GIT_"):
		return "git-misconfiguration"
	default:
		return "iac-misconfiguration"
	}
}

// scanTarget runs Checkov against a single target directory.
func (s *CheckovScanner) scanTarget(ctx context.Context, target string) ([]byte, error) {
	// Resolve absolute path
	absPath, err := filepath.Abs(target)
	if err != nil {
		return nil, fmt.Errorf("checkov: failed to resolve target path: %w", err)
	}

	args := []string{
		"--directory", absPath,
		"--output", "json",
		"--quiet",
		"--compact",
		"--framework", "all", // Scan all IaC frameworks
	}

	// Execute scan using common helper
	output, err := ExecuteScanner(ctx, "checkov", args, s.config)
	if err != nil {
		// Checkov exits with non-zero code when it finds issues (exit code 1)
		// This is expected behavior, so we check if we have valid output
		if ok, _ := HandleNonZeroExit(err, 1); ok && len(output) > 0 {
			return output, nil
		}
		// Check for command not found
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 127 {
			return nil, fmt.Errorf("checkov: command not found: %w", err)
		}
		// Other errors
		if exitErr, ok := err.(*exec.ExitError); ok && len(exitErr.Stderr) > 0 {
			return nil, fmt.Errorf("checkov: execution failed: %s", string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("checkov: execution error: %w", err)
	}

	return output, nil
}

// getVersion returns the Checkov version.
func (s *CheckovScanner) getVersion(ctx context.Context) string {
	return GetScannerVersion(ctx, "checkov", "--version", func(output []byte) string {
		// Checkov outputs version directly
		return strings.TrimSpace(string(output))
	})
}

// CheckovReport represents the Checkov JSON output structure.
type CheckovReport struct {
	Results             CheckovResults       `json:"results"`
	CheckType           string               `json:"check_type"`
	SecretsFailedChecks []CheckovSecretCheck `json:"secrets_failed_checks,omitempty"`
	Summary             CheckovSummary       `json:"summary"`
}

// CheckovResults represents the results field that contains the failed checks.
type CheckovResults struct {
	FailedChecks  []CheckovFailedCheck `json:"failed_checks"`
	PassedChecks  []any                `json:"passed_checks,omitempty"`
	SkippedChecks []any                `json:"skipped_checks,omitempty"`
}

// CheckovFailedCheck represents a failed check from Checkov.
type CheckovFailedCheck struct {
	CodeBlock       any            `json:"code_block"`
	CheckResult     map[string]any `json:"check_result"`
	CheckID         string         `json:"check_id"`
	CheckName       string         `json:"check_name"`
	CheckClass      string         `json:"check_class"`
	Description     string         `json:"description"`
	FilePath        string         `json:"file_path"`
	Resource        string         `json:"resource"`
	ResourceAddress string         `json:"resource_address"`
	Severity        string         `json:"severity"`
	Guideline       string         `json:"guideline"`
	FileLineRange   []int          `json:"file_line_range"`
}

// CheckovSecretCheck represents a secret detected by Checkov.
type CheckovSecretCheck struct {
	CheckID    string `json:"check_id"`
	CheckName  string `json:"check_name"`
	FilePath   string `json:"file_path"`
	SecretType string `json:"secret_type"`
	LineNumber int    `json:"line_number"`
}

// CheckovSummary represents the summary of a Checkov scan.
type CheckovSummary struct {
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	Skipped int `json:"skipped"`
}
