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

// NucleiScanner implements web vulnerability scanning using Nuclei.
type NucleiScanner struct {
	*BaseScanner
	endpoints []string
}

// NewNucleiScanner creates a new Nuclei scanner instance.
func NewNucleiScanner(cfg Config, endpoints []string) *NucleiScanner {
	return NewNucleiScannerWithLogger(cfg, endpoints, logger.GetGlobalLogger())
}

// NewNucleiScannerWithLogger creates a new Nuclei scanner instance with a custom logger.
func NewNucleiScannerWithLogger(cfg Config, endpoints []string, log logger.Logger) *NucleiScanner {
	return &NucleiScanner{
		BaseScanner: NewBaseScannerWithLogger("nuclei", cfg, log),
		endpoints:   endpoints,
	}
}

// Scan executes Nuclei against configured endpoints.
func (s *NucleiScanner) Scan(ctx context.Context) (*models.ScanResult, error) {
	startTime := time.Now()
	result := &models.ScanResult{
		Scanner:   s.Name(),
		Version:   s.version,
		StartTime: startTime,
	}

	if len(s.endpoints) == 0 {
		result.EndTime = time.Now()
		return result, nil
	}

	var allFindings []models.Finding

	// Run Nuclei with all endpoints at once for efficiency
	findings, err := s.runNuclei(ctx, s.endpoints)
	if err != nil {
		result.Error = err.Error()
	} else {
		allFindings = append(allFindings, findings...)
	}

	result.Findings = allFindings
	result.EndTime = time.Now()
	return result, nil
}

// runNuclei executes Nuclei against the given endpoints.
func (s *NucleiScanner) runNuclei(ctx context.Context, endpoints []string) ([]models.Finding, error) {
	// Build command arguments
	args := []string{
		"-json",
		"-severity", "info,low,medium,high,critical",
		"-timeout", "30",
		"-rate-limit", "10",
		"-no-update-templates",
	}

	// Add endpoints
	for _, endpoint := range endpoints {
		args = append(args, "-u", endpoint)
	}

	cmd := exec.CommandContext(ctx, "nuclei", args...)
	// Add environment variables
	if s.config.Env != nil {
		for k, v := range s.config.Env {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
		}
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Nuclei returns non-zero exit code if vulnerabilities are found
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 127 {
			return nil, NewScannerError(s.Name(), "nuclei not found", err)
		}
		// For other non-zero exit codes, we might still have findings
	}

	if len(output) == 0 {
		return []models.Finding{}, nil
	}

	return s.ParseResults(output)
}

// ParseResults parses Nuclei's JSON output into findings.
func (s *NucleiScanner) ParseResults(raw []byte) ([]models.Finding, error) {
	var findings []models.Finding

	// Nuclei outputs one JSON object per line (NDJSON format)
	lines := strings.Split(string(raw), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var result nucleiResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			// Skip malformed lines
			continue
		}

		finding := s.resultToFinding(result)
		if err := finding.IsValid(); err == nil {
			findings = append(findings, *finding)
		}
	}

	return findings, nil
}

// resultToFinding converts a Nuclei result to a finding.
func (s *NucleiScanner) resultToFinding(result nucleiResult) *models.Finding {

	// Map template categories to finding types
	findingType := s.mapTemplateToType(result.TemplateID, result.Info.Tags)

	// Create finding
	finding := models.NewFinding(
		s.Name(),
		findingType,
		result.Host,
		fmt.Sprintf("%s:%s", result.Host, result.MatchedAt),
	)
	finding.Title = result.Info.Name
	finding.Description = s.buildDescription(result)
	finding.Severity = models.NormalizeSeverity(result.Info.Severity)

	// Add metadata
	finding.Metadata = map[string]string{
		"template_id":   result.TemplateID,
		"template_name": result.Info.Name,
		"matched_at":    result.MatchedAt,
		"type":          result.Type,
		"ip":            result.IP,
		"timestamp":     result.Timestamp,
	}

	if result.Info.Description != "" {
		finding.Metadata["template_description"] = result.Info.Description
	}

	if result.Info.Reference != "" {
		finding.Metadata["reference"] = result.Info.Reference
	}

	if result.Info.Tags != "" {
		finding.Metadata["tags"] = result.Info.Tags
	}

	if len(result.ExtractedResults) > 0 {
		finding.Metadata["extracted"] = strings.Join(result.ExtractedResults, ", ")
	}

	return finding
}

// buildDescription creates a comprehensive description from the Nuclei result.
func (s *NucleiScanner) buildDescription(result nucleiResult) string {
	parts := []string{}

	if result.Info.Description != "" {
		parts = append(parts, result.Info.Description)
	}

	parts = append(parts, fmt.Sprintf("Detected at: %s", result.MatchedAt))

	if result.Info.Reference != "" {
		parts = append(parts, fmt.Sprintf("Reference: %s", result.Info.Reference))
	}

	if len(result.ExtractedResults) > 0 {
		parts = append(parts, fmt.Sprintf("Extracted: %s", strings.Join(result.ExtractedResults, ", ")))
	}

	return strings.Join(parts, "\n\n")
}

// mapTemplateToType maps Nuclei template IDs and tags to finding types.
func (s *NucleiScanner) mapTemplateToType(templateID, tags string) string {
	// Check for CVE patterns
	if strings.HasPrefix(templateID, "CVE-") || strings.HasPrefix(templateID, "cve-") {
		return "CVE"
	}

	// Check tags for categorization
	tagList := strings.Split(strings.ToLower(tags), ",")
	for _, tag := range tagList {
		tag = strings.TrimSpace(tag)
		switch tag {
		case "sqli", "sql-injection":
			return "SQL Injection"
		case "xss", "cross-site-scripting":
			return "Cross-Site Scripting"
		case "lfi", "local-file-inclusion":
			return "Local File Inclusion"
		case "rce", "remote-code-execution":
			return "Remote Code Execution"
		case "ssrf", "server-side-request-forgery":
			return "SSRF"
		case "xxe", "xml-external-entity":
			return "XXE"
		case "config", "misconfig", "misconfiguration":
			return "Misconfiguration"
		case "exposure", "exposed":
			return "Information Exposure"
		case "auth", "authentication":
			return "Authentication Issue"
		}
	}

	// Check template ID patterns
	switch {
	case strings.Contains(templateID, "-detect"):
		return "Technology Detection"
	case strings.Contains(templateID, "-panel"):
		return "Admin Panel Exposure"
	case strings.Contains(templateID, "-config"):
		return "Configuration Issue"
	case strings.Contains(templateID, "-disclosure"):
		return "Information Disclosure"
	default:
		return "Web Vulnerability"
	}
}

// nucleiResult represents a single Nuclei finding.
type nucleiResult struct {
	Info             nucleiInfo `json:"info"`
	TemplateID       string     `json:"template-id"`
	Type             string     `json:"type"`
	Host             string     `json:"host"`
	MatchedAt        string     `json:"matched-at"`
	IP               string     `json:"ip"`
	Timestamp        string     `json:"timestamp"`
	ExtractedResults []string   `json:"extracted-results,omitempty"`
}

// nucleiInfo represents the info section of a Nuclei result.
type nucleiInfo struct {
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Description string `json:"description,omitempty"`
	Reference   string `json:"reference,omitempty"`
	Tags        string `json:"tags,omitempty"`
}
