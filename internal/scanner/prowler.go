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

	"github.com/Veraticus/prismatic/internal/models"
	"github.com/Veraticus/prismatic/pkg/logger"
)

// ProwlerScanner implements AWS security scanning using Prowler.
type ProwlerScanner struct {
	*BaseScanner
	profiles []string
	regions  []string
	services []string
}

// NewProwlerScanner creates a new Prowler scanner instance.
func NewProwlerScanner(config Config, profiles, regions, services []string) *ProwlerScanner {
	return NewProwlerScannerWithLogger(config, profiles, regions, services, logger.GetGlobalLogger())
}

// NewProwlerScannerWithLogger creates a new Prowler scanner instance with a custom logger.
func NewProwlerScannerWithLogger(config Config, profiles, regions, services []string, log logger.Logger) *ProwlerScanner {
	// Default to all regions if none specified
	if len(regions) == 0 {
		regions = []string{"all"}
	}

	return &ProwlerScanner{
		BaseScanner: NewBaseScannerWithLogger("prowler", config, log),
		profiles:    profiles,
		regions:     regions,
		services:    services,
	}
}

// Scan executes Prowler against configured AWS accounts.
func (s *ProwlerScanner) Scan(ctx context.Context) (*models.ScanResult, error) {
	startTime := time.Now()

	result := &models.ScanResult{
		Scanner:   s.Name(),
		Version:   s.getVersion(ctx),
		StartTime: startTime,
		Findings:  []models.Finding{},
	}

	// Scan each profile
	for _, profile := range s.profiles {
		if err := ctx.Err(); err != nil {
			result.EndTime = time.Now()
			result.Error = fmt.Sprintf("scan canceled: %v", err)
			return result, nil
		}

		output, err := s.scanProfile(ctx, profile)
		if err != nil {
			// Log error but continue with other profiles
			if s.config.Debug {
				s.logger.Warn("Prowler scan failed", "profile", profile, "error", err)
			}
			continue
		}

		findings, err := s.ParseResults(output)
		if err != nil {
			if s.config.Debug {
				s.logger.Warn("Failed to parse Prowler results", "profile", profile, "error", err)
			}
			continue
		}

		result.Findings = append(result.Findings, findings...)
	}

	result.EndTime = time.Now()
	return result, nil
}

// ParseResults converts Prowler JSON output to normalized findings.
func (s *ProwlerScanner) ParseResults(raw []byte) ([]models.Finding, error) {
	// Try parsing as JSON-OCSF format first (Prowler v4)
	findings, err := s.parseOCSFFormat(raw)
	if err == nil && len(findings) > 0 {
		return findings, nil
	}

	// Fall back to native JSON format (Prowler v3)
	return s.parseNativeFormat(raw)
}

// parseOCSFFormat parses Prowler v4 OCSF JSON output.
func (s *ProwlerScanner) parseOCSFFormat(raw []byte) ([]models.Finding, error) {
	// First check if this is OCSF format by looking for metadata field
	var testFormat []map[string]any
	if err := json.Unmarshal(raw, &testFormat); err == nil && len(testFormat) > 0 {
		if _, hasMetadata := testFormat[0]["metadata"]; !hasMetadata {
			// This is not OCSF format
			return nil, NewScannerError(s.Name(), "parse", fmt.Errorf("not OCSF format"))
		}
	}

	var checks []ProwlerOCSFCheck

	// Try parsing as array first
	if err := json.Unmarshal(raw, &checks); err != nil {
		// Try parsing as NDJSON (newline-delimited)
		checks = s.parseNDJSONOCSF(raw)
		if len(checks) == 0 {
			return nil, NewScannerError(s.Name(), "parse", fmt.Errorf("failed to parse OCSF format"))
		}
	}

	// Pre-allocate with total checks size to avoid reallocations during filtering
	findings := make([]models.Finding, 0, len(checks))

	for _, check := range checks {
		// Only process failed checks
		if check.Status != "FAIL" {
			continue
		}

		// Extract resource information
		resource := "unknown"
		location := ""
		if len(check.Resources) > 0 {
			resource = check.Resources[0].UID
			location = fmt.Sprintf("%s:%s", check.Resources[0].Region, check.Resources[0].Type)
		}

		finding := models.NewFinding(
			s.Name(),
			check.Finding.Type,
			resource,
			location,
		)

		finding.Severity = models.NormalizeSeverity(check.Severity)
		finding.Title = check.Finding.Title
		finding.Description = check.Finding.Desc
		finding.Remediation = check.Finding.Remediation.Desc
		finding.Impact = check.StatusDetail

		// Add references
		finding.References = check.Finding.Remediation.References

		// Add metadata
		finding.Metadata["check_id"] = check.Metadata.EventCode
		finding.Metadata["service"] = check.Finding.Service
		if len(check.Resources) > 0 {
			finding.Metadata["region"] = check.Resources[0].Region
		}
		finding.Metadata["compliance"] = strings.Join(check.Compliance, ", ")

		findings = append(findings, *finding)
	}

	return findings, nil
}

// parseNativeFormat parses Prowler v3 native JSON output.
func (s *ProwlerScanner) parseNativeFormat(raw []byte) ([]models.Finding, error) {
	var checks []ProwlerNativeCheck

	// Try parsing as array first
	if err := json.Unmarshal(raw, &checks); err != nil {
		// Try parsing as NDJSON (newline-delimited)
		checks = s.parseNDJSONNative(raw)
		if len(checks) == 0 {
			return nil, NewScannerError(s.Name(), "parse", fmt.Errorf("failed to parse native format"))
		}
	}

	// Pre-allocate with total checks size to avoid reallocations during filtering
	findings := make([]models.Finding, 0, len(checks))

	for _, check := range checks {
		// Only process failed checks
		if check.Status != "FAIL" {
			continue
		}

		// Use ResourceArn if available, otherwise ResourceID
		resource := check.ResourceArn
		if resource == "" && check.ResourceID != "" {
			resource = check.ResourceID
		}
		if resource == "" {
			resource = "unknown"
		}

		finding := models.NewFinding(
			s.Name(),
			s.mapCheckToType(check.CheckID),
			resource,
			fmt.Sprintf("%s:%s", check.Region, check.ResourceType),
		)

		finding.Severity = models.NormalizeSeverity(check.Severity)
		finding.Title = check.CheckTitle
		finding.Description = check.Description
		finding.Impact = check.Risk

		// Build remediation
		remediation := ""
		if check.Remediation.Recommendation.Text != "" {
			remediation = check.Remediation.Recommendation.Text
		}
		if check.Remediation.Code.CLI != "" {
			remediation += fmt.Sprintf("\n\nCLI Command:\n%s", check.Remediation.Code.CLI)
		}
		finding.Remediation = remediation

		// Add references
		if check.Remediation.Recommendation.URL != "" {
			finding.References = []string{check.Remediation.Recommendation.URL}
		}

		// Add metadata
		finding.Metadata["check_id"] = check.CheckID
		finding.Metadata["account_id"] = check.AccountID
		finding.Metadata["service"] = check.ServiceName
		finding.Metadata["region"] = check.Region
		finding.Metadata["resource_id"] = check.ResourceID
		finding.Metadata["status_extended"] = check.StatusExtended

		findings = append(findings, *finding)
	}

	return findings, nil
}

// parseNDJSONOCSF parses newline-delimited JSON for OCSF format.
func (s *ProwlerScanner) parseNDJSONOCSF(raw []byte) []ProwlerOCSFCheck {
	var results []ProwlerOCSFCheck
	lines := strings.Split(string(raw), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var item ProwlerOCSFCheck
		if err := json.Unmarshal([]byte(line), &item); err == nil {
			results = append(results, item)
		}
	}

	return results
}

// parseNDJSONNative parses newline-delimited JSON for native format.
func (s *ProwlerScanner) parseNDJSONNative(raw []byte) []ProwlerNativeCheck {
	var results []ProwlerNativeCheck
	lines := strings.Split(string(raw), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var item ProwlerNativeCheck
		if err := json.Unmarshal([]byte(line), &item); err == nil {
			results = append(results, item)
		}
	}

	return results
}

// scanProfile runs Prowler against a single AWS profile.
func (s *ProwlerScanner) scanProfile(ctx context.Context, profile string) ([]byte, error) {
	// Create output directory
	outputDir := filepath.Join(s.config.WorkingDir, "prowler-output")

	args := []string{
		"aws",
		"--output-modes", "json-ocsf",
		"--output-directory", outputDir,
		"--profile", profile,
		"--status", "FAIL", // Only get failed checks
	}

	// Add regions if specified
	if len(s.regions) > 0 && s.regions[0] != "all" {
		args = append(args, "--filter-region", strings.Join(s.regions, " "))
	}

	// Add services if specified
	if len(s.services) > 0 {
		args = append(args, "--services", strings.Join(s.services, " "))
	}

	cmd := exec.CommandContext(ctx, "prowler", args...)
	cmd.Dir = s.config.WorkingDir

	// Convert env map to slice of strings
	if s.config.Env != nil {
		for k, v := range s.config.Env {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
		}
	}

	// Run Prowler
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Prowler returns non-zero exit code when it finds issues, which is expected
		exitErr, ok := err.(*exec.ExitError)
		if !ok || exitErr.ExitCode() != 3 {
			// Exit code 3 means findings were found, which is expected
			return nil, fmt.Errorf("prowler failed: %s", string(output))
		}
	}

	// Find and read the output file
	outputFiles, err := filepath.Glob(filepath.Join(outputDir, "*", "*.ocsf.json"))
	if err != nil || len(outputFiles) == 0 {
		// Try native format
		outputFiles, err = filepath.Glob(filepath.Join(outputDir, "*", "*.json"))
		if err != nil || len(outputFiles) == 0 {
			return nil, fmt.Errorf("no output files found")
		}
	}

	// Read the most recent output file
	return os.ReadFile(outputFiles[len(outputFiles)-1])
}

// getVersion returns the Prowler version.
func (s *ProwlerScanner) getVersion(ctx context.Context) string {
	cmd := exec.CommandContext(ctx, "prowler", "--version")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}

	// Parse version from output like "prowler 4.0.0"
	parts := strings.Fields(string(output))
	if len(parts) >= 2 {
		return parts[1]
	}

	return "unknown"
}

// mapCheckToType maps Prowler check IDs to finding types.
func (s *ProwlerScanner) mapCheckToType(checkID string) string {
	// Extract the service and category from check ID
	// Format: service_category_specific_check
	parts := strings.Split(checkID, "_")
	if len(parts) < 2 {
		return "misconfiguration"
	}

	// Map common patterns
	switch {
	case strings.Contains(checkID, "_encryption_"):
		return "encryption"
	case strings.Contains(checkID, "_public_"):
		return "internet-exposed"
	case strings.Contains(checkID, "_logging_"):
		return "logging"
	case strings.Contains(checkID, "_backup_"):
		return "resilience"
	case strings.HasPrefix(checkID, "iam_"):
		return "iam"
	case strings.Contains(checkID, "_secret") || strings.Contains(checkID, "_key_") || strings.Contains(checkID, "_password"):
		return "secrets"
	default:
		return "misconfiguration"
	}
}

// ProwlerOCSFCheck represents a Prowler v4 OCSF format check result.
type ProwlerOCSFCheck struct {
	Metadata struct {
		EventCode string `json:"event_code"`
		Product   struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"product"`
	} `json:"metadata"`
	Severity     string `json:"severity"`
	Status       string `json:"status"`
	StatusCode   string `json:"status_code"`
	StatusDetail string `json:"status_detail"`
	Message      string `json:"message"`
	Finding      struct {
		UID         string `json:"uid"`
		Type        string `json:"type"`
		Title       string `json:"title"`
		Desc        string `json:"desc"`
		Service     string `json:"service"`
		Remediation struct {
			Desc       string   `json:"desc"`
			References []string `json:"references"`
		} `json:"remediation"`
	} `json:"finding"`
	Resources []struct {
		UID    string `json:"uid"`
		Type   string `json:"type"`
		Region string `json:"region"`
	} `json:"resources"`
	Compliance []string `json:"compliance"`
	SeverityID int      `json:"severity_id"`
}

// ProwlerNativeCheck represents a Prowler v3 native format check result.
type ProwlerNativeCheck struct {
	Provider       string `json:"Provider"`
	AccountID      string `json:"AccountId"`
	Region         string `json:"Region"`
	CheckID        string `json:"CheckID"`
	CheckTitle     string `json:"CheckTitle"`
	ServiceName    string `json:"ServiceName"`
	Status         string `json:"Status"`
	StatusExtended string `json:"StatusExtended"`
	Severity       string `json:"Severity"`
	ResourceID     string `json:"ResourceId"`
	ResourceArn    string `json:"ResourceArn"`
	ResourceType   string `json:"ResourceType"`
	Description    string `json:"Description"`
	Risk           string `json:"Risk"`
	Remediation    struct {
		Code struct {
			CLI string `json:"CLI"`
		} `json:"Code"`
		Recommendation struct {
			Text string `json:"Text"`
			URL  string `json:"Url"`
		} `json:"Recommendation"`
	} `json:"Remediation"`
}
