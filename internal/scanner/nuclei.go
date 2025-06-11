package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/joshsymonds/prismatic/pkg/logger"
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
	s := &NucleiScanner{
		BaseScanner: NewBaseScannerWithLogger("nuclei", cfg, log),
		endpoints:   endpoints,
	}
	s.version = s.getVersion()
	log.Info("Nuclei scanner created", "endpoints", endpoints, "endpoint_count", len(endpoints))
	return s
}

// getVersion retrieves the version of Nuclei.
func (s *NucleiScanner) getVersion() string {
	return GetScannerVersion(context.Background(), "nuclei", "-version", func(output []byte) string {
		// Nuclei version output format: "Nuclei Engine Version: v3.1.2"
		version := strings.TrimSpace(string(output))
		if parts := strings.Split(version, ": "); len(parts) >= 2 {
			return strings.TrimSpace(parts[len(parts)-1])
		}
		return version
	})
}

// Scan executes Nuclei against configured endpoints.
func (s *NucleiScanner) Scan(ctx context.Context) (*models.ScanResult, error) {
	startTime := time.Now()
	result := &models.ScanResult{
		Scanner:   s.Name(),
		Version:   s.version,
		StartTime: startTime,
	}

	s.logger.Info("Nuclei Scan called", "endpoints_in_scanner", s.endpoints, "count", len(s.endpoints))

	if len(s.endpoints) == 0 {
		s.logger.Info("Nuclei: No endpoints configured, skipping scan")
		result.EndTime = time.Now()
		return result, ErrNoTargets
	}

	s.logger.Info("Nuclei: Scanning endpoints", "count", len(s.endpoints), "endpoints", s.endpoints)

	var allFindings []models.Finding

	// Create a timeout context if not already present
	scanCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		// Increase timeout to 30 minutes for Nuclei scans
		scanCtx, cancel = context.WithTimeout(ctx, 30*time.Minute)
		defer cancel()
	}

	// Run Nuclei with all endpoints at once for efficiency
	findings, err := s.runNuclei(scanCtx, s.endpoints)
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
		"-j", // JSON Lines output
		"-severity", "info,low,medium,high,critical",
		"-timeout", "30",
		"-rate-limit", "10",
		"-nc",    // No color in output
		"-stats", // Show scanning statistics
	}

	// Add endpoints
	if len(endpoints) == 0 {
		s.logger.Warn("No endpoints provided to runNuclei!")
		return []models.Finding{}, fmt.Errorf("no endpoints provided")
	}

	for _, endpoint := range endpoints {
		args = append(args, "-u", endpoint)
	}

	// Execute command directly to handle Nuclei's output properly
	cmd := exec.CommandContext(ctx, "nuclei", args...)

	// Always set a working directory for nuclei to prevent it from creating files in the project root
	if s.config.WorkingDir != "" {
		// Use the scanner's working directory if available
		cmd.Dir = s.config.WorkingDir
	} else {
		// Use system temp directory as working directory
		// Don't create a new directory - just use the system temp
		cmd.Dir = os.TempDir()
	}

	// Set environment if provided
	if s.config.Env != nil {
		env := os.Environ()
		for k, v := range s.config.Env {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
		cmd.Env = env
	}

	// Check if nuclei templates exist in possible locations
	homeDir, _ := os.UserHomeDir()
	templatePaths := []string{
		filepath.Join(homeDir, "nuclei-templates"),
		filepath.Join(homeDir, ".local", "nuclei-templates"),
	}

	templatesFound := false
	for _, path := range templatePaths {
		if _, err := os.Stat(path); err == nil {
			s.logger.Info("Nuclei templates found", "path", path)
			templatesFound = true
			break
		}
	}

	if !templatesFound {
		s.logger.Info("Nuclei templates not found, downloading...")

		// Run nuclei with -update-templates to download templates
		updateCmd := exec.CommandContext(ctx, "nuclei", "-update-templates")
		// Use the same working directory as the main command
		if s.config.WorkingDir != "" {
			updateCmd.Dir = s.config.WorkingDir
		} else {
			updateCmd.Dir = os.TempDir()
		}
		updateOutput, updateErr := updateCmd.CombinedOutput()

		if updateErr != nil {
			s.logger.Error("Failed to download nuclei templates", "error", updateErr, "output", string(updateOutput))
			return nil, fmt.Errorf("failed to download nuclei templates: %w", updateErr)
		}

		outputLen := len(updateOutput)
		previewLen := 500
		if outputLen < previewLen {
			previewLen = outputLen
		}
		s.logger.Info("Nuclei templates downloaded successfully", "output_preview", string(updateOutput[:previewLen]))
	}

	// Log the full command being executed
	fullCmd := append([]string{"nuclei"}, args...)
	s.logger.Info("Running nuclei command",
		"endpoints", endpoints,
		"endpoint_count", len(endpoints),
		"args", args,
		"full_command", strings.Join(fullCmd, " "))

	// Use pipes to capture output while respecting context cancellation
	startTime := time.Now()

	// Create pipes for stdout and stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start nuclei: %w", err)
	}

	// Read output in background
	var output []byte
	outputChan := make(chan []byte, 1)

	go func() {
		// Read both stdout and stderr
		var buf []byte
		// Read stdout
		stdoutBytes := make([]byte, 0, 1024*1024) // Pre-allocate 1MB
		for {
			tmp := make([]byte, 8192)
			n, err := stdout.Read(tmp)
			if n > 0 {
				stdoutBytes = append(stdoutBytes, tmp[:n]...)
			}
			if err != nil {
				break
			}
		}

		// Read stderr
		stderrBytes := make([]byte, 0, 1024*1024) // Pre-allocate 1MB
		for {
			tmp := make([]byte, 8192)
			n, err := stderr.Read(tmp)
			if n > 0 {
				stderrBytes = append(stderrBytes, tmp[:n]...)
			}
			if err != nil {
				break
			}
		}

		// Combine stdout and stderr
		buf = append(buf, stdoutBytes...)
		buf = append(buf, stderrBytes...)
		outputChan <- buf
	}()

	// Wait for command completion or context cancellation
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-ctx.Done():
		// Context canceled, kill the process
		s.logger.Warn("Nuclei scan timeout, killing process")
		if killErr := cmd.Process.Kill(); killErr != nil {
			s.logger.Error("Failed to kill nuclei process", "error", killErr)
		}
		return nil, fmt.Errorf("nuclei scan timeout after %v: %w", time.Since(startTime), ctx.Err())

	case err = <-done:
		// Command completed
		select {
		case output = <-outputChan:
			// Got output
		case <-time.After(5 * time.Second):
			// Timeout waiting for output
			s.logger.Warn("Timeout waiting for nuclei output after process completion")
			output = []byte{}
		}
	}

	duration := time.Since(startTime)

	// Check if context was canceled
	if ctx.Err() != nil {
		// Include output in error for debugging
		if len(output) > 0 {
			// Extract non-JSON error messages
			var errorLines []string
			for _, line := range strings.Split(string(output), "\n") {
				trimmed := strings.TrimSpace(line)
				if trimmed != "" && !strings.HasPrefix(trimmed, "{") {
					errorLines = append(errorLines, trimmed)
				}
			}
			if len(errorLines) > 0 {
				return nil, fmt.Errorf("nuclei scan canceled: %w. Output: %s", ctx.Err(), strings.Join(errorLines, "; "))
			}
		}
		return nil, fmt.Errorf("nuclei scan canceled: %w", ctx.Err())
	}

	if err != nil {
		s.logger.Debug("Nuclei completed with error", "error", err, "output_len", len(output))
	}

	// Extract JSON lines from output (nuclei outputs JSON to stdout even with other messages)
	var jsonLines []byte
	var errorLines []string
	for _, line := range strings.Split(string(output), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}") {
			jsonLines = append(jsonLines, []byte(trimmed+"\n")...)
		} else if err != nil {
			// Capture non-JSON lines as potential error messages
			errorLines = append(errorLines, trimmed)
		}
	}

	// Always log the output for debugging with execution time
	s.logger.Info("Nuclei completed", "duration", duration.String(), "output_size", len(output), "json_lines", len(jsonLines), "error_lines", len(errorLines))

	// Save raw output for debugging if we have a working directory
	if s.config.WorkingDir != "" && strings.Contains(s.config.WorkingDir, "data/scans") {
		debugFile := filepath.Join(s.config.WorkingDir, fmt.Sprintf("nuclei-debug-%s.log", time.Now().Format("20060102-150405")))
		if debugErr := os.WriteFile(debugFile, output, 0600); debugErr == nil {
			s.logger.Info("Nuclei debug output saved", "file", debugFile)
		}
	}

	// Log the output for debugging
	if len(output) > 0 {
		lines := strings.Split(string(output), "\n")

		// Log first few lines
		preview := lines
		if len(lines) > 10 {
			preview = lines[:10]
		}
		s.logger.Info("Nuclei output preview", "lines", preview)

		// Check if we see template statistics
		for _, line := range lines {
			if strings.Contains(line, "Templates loaded for scan") ||
				strings.Contains(line, "Templates loaded for current scan") ||
				strings.Contains(line, "[INF]") {
				s.logger.Info("Nuclei template info", "line", line)
			}
		}

		if len(errorLines) > 0 && len(errorLines) <= 10 {
			s.logger.Info("Nuclei non-JSON output", "lines", errorLines)
		}
	}

	if len(jsonLines) == 0 {
		if err != nil {
			// Check if it's a command not found error
			if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 127 {
				return nil, fmt.Errorf("nuclei: command not found: %w", err)
			}
			// Include captured error output
			if len(errorLines) > 0 {
				return nil, fmt.Errorf("nuclei failed: %w. Output: %s", err, strings.Join(errorLines, "; "))
			}
			s.logger.Info("Nuclei completed with error but no findings", "error", err)
		} else {
			s.logger.Info("Nuclei completed successfully with no findings")
		}
		return []models.Finding{}, nil
	}

	return s.ParseResults(jsonLines)
}

// ParseResults parses Nuclei's JSON output into findings.
func (s *NucleiScanner) ParseResults(raw []byte) ([]models.Finding, error) {
	var results []nucleiResult

	// Use the common NDJSON parser
	if err := ParseNDJSON(raw, &results); err != nil {
		return nil, err
	}

	var findings []models.Finding
	for _, result := range results {
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
	tags := strings.Join(result.Info.Tags, ",")
	findingType := s.mapTemplateToType(result.TemplateID, tags)

	// Create finding
	finding := models.NewFinding(
		s.Name(),
		findingType,
		result.Host,
		fmt.Sprintf("%s:%s", result.Host, result.MatchedAt),
	).WithSeverity(result.Info.Severity)
	finding.Title = result.Info.Name
	finding.Description = s.buildDescription(result)

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

	if len(result.Info.Tags) > 0 {
		finding.Metadata["tags"] = tags // We already joined them above
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
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Description string   `json:"description,omitempty"`
	Reference   string   `json:"reference,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Author      []string `json:"author,omitempty"`
}
