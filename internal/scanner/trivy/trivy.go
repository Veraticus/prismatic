// Package trivy implements a native Trivy scanner using the streaming architecture.
package trivy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/joshsymonds/prismatic/internal/scanner"
)

// contextKey is a type for context keys to avoid collisions.
type contextKey string

const (
	// Context keys for Trivy authentication.
	contextKeyUsername contextKey = "trivy-username"
	contextKeyPassword contextKey = "trivy-password"
)

// Config provides Trivy-specific configuration.
// It implements scanner.Config.
type Config struct {
	CacheDir      string
	Format        string
	DBRepository  string
	Severities    []string
	VulnTypes     []string
	Timeout       time.Duration
	Parallel      int
	IgnoreUnfixed bool
	OfflineMode   bool
	SkipDBUpdate  bool
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	// Validate severities
	validSeverities := map[string]bool{
		"CRITICAL": true,
		"HIGH":     true,
		"MEDIUM":   true,
		"LOW":      true,
		"UNKNOWN":  true,
	}

	for _, sev := range c.Severities {
		if !validSeverities[sev] {
			return fmt.Errorf("invalid severity: %s", sev)
		}
	}

	// Validate vuln types
	validTypes := map[string]bool{
		"vuln":      true,
		"secret":    true,
		"misconfig": true,
		"license":   true,
	}

	for _, vt := range c.VulnTypes {
		if !validTypes[vt] {
			return fmt.Errorf("invalid vulnerability type: %s", vt)
		}
	}

	// Validate timeout
	if c.Timeout < 0 {
		return fmt.Errorf("timeout cannot be negative")
	}

	// Validate parallel
	if c.Parallel < 0 {
		return fmt.Errorf("parallel cannot be negative")
	}

	return nil
}

// DefaultConfig returns sensible defaults for Trivy.
func DefaultConfig() *Config {
	return &Config{
		CacheDir:      filepath.Join(os.TempDir(), "trivy-cache"),
		Severities:    []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"},
		VulnTypes:     []string{"vuln", "secret", "misconfig"},
		Timeout:       30 * time.Minute,
		IgnoreUnfixed: false,
		OfflineMode:   false,
		SkipDBUpdate:  false,
		Parallel:      3,
		Format:        "json",
		DBRepository:  "ghcr.io/aquasecurity/trivy-db",
	}
}

// Scanner implements the scanner.Scanner interface for Trivy.
type Scanner struct {
	config        *Config
	cancel        context.CancelFunc
	name          string
	targets       scanner.Targets
	mu            sync.Mutex
	scanning      bool
	dbInitialized bool
	dbInitMutex   sync.Mutex
}

// Factory implements scanner.Factory for Trivy.
type Factory struct{}

// Name returns the scanner type name.
func (f *Factory) Name() string {
	return "trivy"
}

// Create builds a new Trivy scanner instance.
func (f *Factory) Create(name string, config scanner.Config, targets scanner.Targets) (scanner.Scanner, error) {
	// Type assert config
	trivyConfig, ok := config.(*Config)
	if !ok {
		return nil, fmt.Errorf("invalid config type: expected *trivy.Config, got %T", config)
	}

	// Validate targets
	if err := validateTargets(targets); err != nil {
		return nil, err
	}

	return &Scanner{
		name:    name,
		config:  trivyConfig,
		targets: targets,
	}, nil
}

// DefaultConfig returns the default configuration.
func (f *Factory) DefaultConfig() scanner.Config {
	return DefaultConfig()
}

// Capabilities returns Trivy's capabilities.
func (f *Factory) Capabilities() scanner.Capabilities {
	return scanner.Capabilities{
		SupportsImages:       true,
		SupportsFilesystems:  true,
		SupportsRepositories: true,
		SupportsCloud:        false, // Trivy doesn't scan cloud directly
		SupportsKubernetes:   true,
		SupportsWeb:          false,
		SupportsConcurrency:  true,
		RequiresNetwork:      true, // For DB updates
		MaxConcurrency:       10,   // Reasonable limit
	}
}

// Name returns the scanner instance name.
func (s *Scanner) Name() string {
	return s.name
}

// ensureTrivyDB ensures the Trivy database is initialized and up to date.
func (s *Scanner) ensureTrivyDB(ctx context.Context) error {
	s.dbInitMutex.Lock()
	defer s.dbInitMutex.Unlock()

	if s.dbInitialized {
		return nil
	}

	// Ensure cache directory exists
	if err := os.MkdirAll(s.config.CacheDir, 0750); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Check if we should skip DB update
	if s.config.SkipDBUpdate || s.config.OfflineMode {
		s.dbInitialized = true
		return nil
	}

	// Download/update the vulnerability database
	args := []string{
		"image",
		"--download-db-only",
		"--cache-dir", s.config.CacheDir,
		"--db-repository", s.config.DBRepository,
	}

	cmd := exec.CommandContext(ctx, "trivy", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// If offline mode, continue anyway
		if s.config.OfflineMode {
			s.dbInitialized = true
			return nil
		}
		return fmt.Errorf("failed to update Trivy database: %w\nstderr: %s", err, stderr.String())
	}

	s.dbInitialized = true
	return nil
}

// Scan executes the Trivy security scan.
func (s *Scanner) Scan(ctx context.Context) (<-chan scanner.Finding, error) {
	// Check if already scanning
	s.mu.Lock()
	if s.scanning {
		s.mu.Unlock()
		return nil, scanner.ErrScanInProgress
	}
	s.scanning = true
	s.mu.Unlock()

	// Create cancellable context
	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	// Check if Trivy is available
	if _, err := exec.LookPath("trivy"); err != nil {
		s.mu.Lock()
		s.scanning = false
		s.mu.Unlock()
		return nil, fmt.Errorf("trivy not found in PATH: %w", err)
	}

	// Ensure Trivy database is initialized
	if err := s.ensureTrivyDB(ctx); err != nil {
		s.mu.Lock()
		s.scanning = false
		s.mu.Unlock()
		return nil, fmt.Errorf("failed to initialize Trivy database: %w", err)
	}

	// Create findings channel
	findings := make(chan scanner.Finding, 100)

	// Start scanning in background
	go func() {
		defer close(findings)
		defer func() {
			s.mu.Lock()
			s.scanning = false
			s.cancel = nil
			s.mu.Unlock()
		}()

		// Create semaphore for parallel scanning
		sem := make(chan struct{}, s.config.Parallel)
		var wg sync.WaitGroup

		// Scan images
		for _, image := range s.targets.Images {
			wg.Add(1)
			go func(img scanner.Image) {
				defer wg.Done()

				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					return
				}

				s.scanImage(ctx, img, findings)
			}(image)
		}

		// Scan filesystems
		for _, fs := range s.targets.Filesystems {
			wg.Add(1)
			go func(filesystem scanner.Filesystem) {
				defer wg.Done()

				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					return
				}

				s.scanFilesystem(ctx, filesystem, findings)
			}(fs)
		}

		// Scan repositories
		for _, repo := range s.targets.Repositories {
			wg.Add(1)
			go func(repository scanner.Repository) {
				defer wg.Done()

				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					return
				}

				s.scanRepository(ctx, repository, findings)
			}(repo)
		}

		// Scan Kubernetes clusters
		for _, cluster := range s.targets.KubernetesClusters {
			wg.Add(1)
			go func(k8s scanner.KubernetesCluster) {
				defer wg.Done()

				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					return
				}

				s.scanKubernetes(ctx, k8s, findings)
			}(cluster)
		}

		// Wait for all scans to complete
		wg.Wait()
	}()

	return findings, nil
}

// Close releases resources.
func (s *Scanner) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cancel != nil {
		s.cancel()
	}

	return nil
}

// runTrivy executes the trivy command and returns the JSON output.
func (s *Scanner) runTrivy(ctx context.Context, args []string) (*TrivyResult, error) {
	// Common arguments
	baseArgs := []string{
		"--format", "json",
		"--cache-dir", s.config.CacheDir,
		"--timeout", fmt.Sprintf("%dm", int(s.config.Timeout.Minutes())),
	}

	// Add severity filter
	if len(s.config.Severities) > 0 {
		baseArgs = append(baseArgs, "--severity", strings.Join(s.config.Severities, ","))
	}

	// Add vulnerability types
	if len(s.config.VulnTypes) > 0 {
		var scanners []string
		for _, vt := range s.config.VulnTypes {
			switch vt {
			case "vuln":
				scanners = append(scanners, "vuln")
			case "secret":
				scanners = append(scanners, "secret")
			case "misconfig":
				scanners = append(scanners, "misconfig", "config")
			case "license":
				scanners = append(scanners, "license")
			}
		}
		baseArgs = append(baseArgs, "--scanners", strings.Join(scanners, ","))
	}

	// Add ignore unfixed
	if s.config.IgnoreUnfixed {
		baseArgs = append(baseArgs, "--ignore-unfixed")
	}

	// Add offline mode
	if s.config.OfflineMode {
		baseArgs = append(baseArgs, "--offline-scan")
	}

	// Add skip-db-update
	if s.config.SkipDBUpdate {
		baseArgs = append(baseArgs, "--skip-db-update")
	}

	// Combine all arguments
	allArgs := make([]string, 0, len(baseArgs)+len(args))
	allArgs = append(allArgs, baseArgs...)
	allArgs = append(allArgs, args...)

	// Execute trivy
	cmd := exec.CommandContext(ctx, "trivy", allArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Check if it's a context cancellation
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("trivy execution failed: %w\nstderr: %s", err, stderr.String())
	}

	// Parse JSON output
	var result TrivyResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return nil, fmt.Errorf("failed to parse trivy output: %w", err)
	}

	return &result, nil
}

// scanImage scans a container image.
func (s *Scanner) scanImage(ctx context.Context, image scanner.Image, findings chan<- scanner.Finding) {
	args := []string{"image"}

	// Add authentication if provided
	if image.Auth != nil {
		if image.Auth.Username != "" && image.Auth.Password != "" {
			// Use environment variables for authentication
			ctx = context.WithValue(ctx, contextKeyUsername, image.Auth.Username)
			ctx = context.WithValue(ctx, contextKeyPassword, image.Auth.Password)
		}
	}

	args = append(args, image.Name)

	result, err := s.runTrivy(ctx, args)
	if err != nil {
		select {
		case findings <- scanner.Finding{Error: fmt.Errorf("failed to scan image %s: %w", image.Name, err)}:
		case <-ctx.Done():
		}
		return
	}

	s.processResults(ctx, result, "image", image.Name, findings)
}

// scanFilesystem scans a filesystem path.
func (s *Scanner) scanFilesystem(ctx context.Context, fs scanner.Filesystem, findings chan<- scanner.Finding) {
	args := []string{"fs"}

	// Add skip-dirs for excludes
	if len(fs.Excludes) > 0 {
		args = append(args, "--skip-dirs", strings.Join(fs.Excludes, ","))
	}

	args = append(args, fs.Path)

	result, err := s.runTrivy(ctx, args)
	if err != nil {
		select {
		case findings <- scanner.Finding{Error: fmt.Errorf("failed to scan filesystem %s: %w", fs.Path, err)}:
		case <-ctx.Done():
		}
		return
	}

	s.processResults(ctx, result, "filesystem", fs.Path, findings)
}

// scanRepository scans a git repository.
func (s *Scanner) scanRepository(ctx context.Context, repo scanner.Repository, findings chan<- scanner.Finding) {
	args := []string{"fs"}

	// For repositories, we scan the filesystem but add context
	args = append(args, repo.Path)

	result, err := s.runTrivy(ctx, args)
	if err != nil {
		select {
		case findings <- scanner.Finding{Error: fmt.Errorf("failed to scan repository %s: %w", repo.Path, err)}:
		case <-ctx.Done():
		}
		return
	}

	s.processResults(ctx, result, "repository", repo.Path, findings)
}

// scanKubernetes scans a Kubernetes cluster.
func (s *Scanner) scanKubernetes(ctx context.Context, cluster scanner.KubernetesCluster, findings chan<- scanner.Finding) {
	args := []string{"k8s"}

	// Add context if specified
	if cluster.Context != "" {
		args = append(args, "--context", cluster.Context)
	}

	// Add namespaces if specified
	if len(cluster.Namespaces) > 0 {
		args = append(args, "--namespace", strings.Join(cluster.Namespaces, ","))
	} else {
		args = append(args, "--all-namespaces")
	}

	// Add cluster name or "cluster"
	args = append(args, "cluster")

	result, err := s.runTrivy(ctx, args)
	if err != nil {
		select {
		case findings <- scanner.Finding{Error: fmt.Errorf("failed to scan kubernetes cluster %s: %w", cluster.Context, err)}:
		case <-ctx.Done():
		}
		return
	}

	s.processResults(ctx, result, "kubernetes", cluster.Context, findings)
}

// processResults converts Trivy results to Prismatic findings.
func (s *Scanner) processResults(ctx context.Context, result *TrivyResult, _, target string, findings chan<- scanner.Finding) {
	for _, targetResult := range result.Results {
		// Process vulnerabilities
		for _, vuln := range targetResult.Vulnerabilities {
			finding := s.createVulnerabilityFinding(vuln, targetResult, target)
			select {
			case findings <- scanner.Finding{Finding: finding}:
			case <-ctx.Done():
				return
			}
		}

		// Process misconfigurations
		for _, misconf := range targetResult.Misconfigurations {
			finding := s.createMisconfigurationFinding(misconf, targetResult, target)
			select {
			case findings <- scanner.Finding{Finding: finding}:
			case <-ctx.Done():
				return
			}
		}

		// Process secrets
		for _, secret := range targetResult.Secrets {
			finding := s.createSecretFinding(secret, targetResult, target)
			select {
			case findings <- scanner.Finding{Finding: finding}:
			case <-ctx.Done():
				return
			}
		}
	}
}

// createVulnerabilityFinding creates a finding from a vulnerability.
func (s *Scanner) createVulnerabilityFinding(vuln TrivyVulnerability, result TrivyTargetResult, target string) *models.Finding {
	// Generate stable ID
	id := generateFindingID(s.name, "vulnerability", target, vuln.VulnerabilityID, vuln.PkgName)

	finding := &models.Finding{
		ID:             id,
		Scanner:        s.name,
		Type:           "vulnerability",
		Severity:       strings.ToLower(vuln.Severity),
		Title:          fmt.Sprintf("%s vulnerability in %s", vuln.VulnerabilityID, vuln.PkgName),
		Description:    vuln.Description,
		Resource:       target,
		Location:       result.Target,
		Metadata:       make(map[string]string),
		DiscoveredDate: time.Now(),
	}

	// Use Trivy's title if available
	if vuln.Title != "" {
		finding.Title = vuln.Title
	}

	// Set description
	if finding.Description == "" {
		finding.Description = fmt.Sprintf(
			"Package %s version %s is vulnerable to %s",
			vuln.PkgName, vuln.InstalledVersion, vuln.VulnerabilityID,
		)
	}

	// Build remediation
	if vuln.FixedVersion != "" {
		finding.Remediation = fmt.Sprintf("Update %s to version %s or later", vuln.PkgName, vuln.FixedVersion)
	} else {
		finding.Remediation = fmt.Sprintf("No fix available yet for %s in %s", vuln.VulnerabilityID, vuln.PkgName)
	}

	// Add references
	if vuln.PrimaryURL != "" {
		finding.References = []string{vuln.PrimaryURL}
	}
	finding.References = append(finding.References, vuln.References...)

	// Set published date if available
	if vuln.PublishedDate != nil {
		finding.PublishedDate = *vuln.PublishedDate
	}

	// Create technical details
	technical := s.createVulnerabilityTechnical(vuln, result)

	// Store technical details in metadata as JSON
	if techJSON, err := json.Marshal(technical); err == nil {
		finding.Metadata["technical_details"] = string(techJSON)
	}

	// Add basic metadata
	finding.Metadata["cve"] = vuln.VulnerabilityID
	finding.Metadata["package"] = vuln.PkgName
	finding.Metadata["version"] = vuln.InstalledVersion
	if vuln.FixedVersion != "" {
		finding.Metadata["fixed_version"] = vuln.FixedVersion
	}

	return finding
}

// createMisconfigurationFinding creates a finding from a misconfiguration.
func (s *Scanner) createMisconfigurationFinding(misconf TrivyMisconfiguration, result TrivyTargetResult, target string) *models.Finding {
	// Generate stable ID
	location := result.Target
	if misconf.CauseMetadata != nil && misconf.CauseMetadata.StartLine > 0 {
		location = fmt.Sprintf("%s:%d", result.Target, misconf.CauseMetadata.StartLine)
	}
	id := generateFindingID(s.name, "misconfiguration", target, misconf.ID, location)

	finding := &models.Finding{
		ID:             id,
		Scanner:        s.name,
		Type:           "misconfiguration",
		Severity:       strings.ToLower(misconf.Severity),
		Title:          misconf.Title,
		Description:    misconf.Description,
		Resource:       target,
		Location:       location,
		Impact:         misconf.Message,
		Remediation:    misconf.Resolution,
		Metadata:       make(map[string]string),
		DiscoveredDate: time.Now(),
	}

	// Add references
	if misconf.PrimaryURL != "" {
		finding.References = []string{misconf.PrimaryURL}
	}
	finding.References = append(finding.References, misconf.References...)

	// Create technical details
	technical := s.createMisconfigurationTechnical(misconf, result)

	// Store technical details in metadata as JSON
	if techJSON, err := json.Marshal(technical); err == nil {
		finding.Metadata["technical_details"] = string(techJSON)
	}

	// Add basic metadata
	finding.Metadata["check_id"] = misconf.ID
	finding.Metadata["check_type"] = misconf.Type
	if misconf.CauseMetadata != nil {
		finding.Metadata["file"] = result.Target
		if misconf.CauseMetadata.StartLine > 0 {
			finding.Metadata["line"] = fmt.Sprintf("%d", misconf.CauseMetadata.StartLine)
		}
	}

	return finding
}

// createSecretFinding creates a finding from a secret.
func (s *Scanner) createSecretFinding(secret TrivySecret, result TrivyTargetResult, target string) *models.Finding {
	// Generate stable ID
	location := fmt.Sprintf("%s:%d", result.Target, secret.StartLine)
	id := generateFindingID(s.name, "secret", target, secret.RuleID, location)

	finding := &models.Finding{
		ID:             id,
		Scanner:        s.name,
		Type:           "secret",
		Severity:       strings.ToLower(secret.Severity),
		Title:          fmt.Sprintf("Exposed %s", secret.Title),
		Description:    fmt.Sprintf("Found %s at line %d", secret.Title, secret.StartLine),
		Resource:       target,
		Location:       location,
		Impact:         "Exposed secrets can lead to unauthorized access and data breaches",
		Remediation:    "Remove the secret from the codebase and rotate it immediately",
		Metadata:       make(map[string]string),
		DiscoveredDate: time.Now(),
		References:     []string{},
	}

	// Create technical details
	technical := s.createSecretTechnical(secret, result)

	// Store technical details in metadata as JSON
	if techJSON, err := json.Marshal(technical); err == nil {
		finding.Metadata["technical_details"] = string(techJSON)
	}

	// Add basic metadata
	finding.Metadata["rule_id"] = secret.RuleID
	finding.Metadata["secret_type"] = secret.Category
	finding.Metadata["file"] = result.Target
	finding.Metadata["line"] = fmt.Sprintf("%d", secret.StartLine)

	return finding
}

// createVulnerabilityTechnical creates technical details for a vulnerability.
func (s *Scanner) createVulnerabilityTechnical(vuln TrivyVulnerability, result TrivyTargetResult) *TrivyTechnical {
	tech := &TrivyTechnical{
		ScannerType:      "vuln",
		Target:           result.Target,
		Class:            result.Class,
		CVE:              vuln.VulnerabilityID,
		CWE:              vuln.CweIDs,
		Package:          vuln.PkgName,
		InstalledVersion: vuln.InstalledVersion,
		FixedVersion:     vuln.FixedVersion,
		PackageType:      result.Type,
		PackagePath:      vuln.PkgPath,
		References:       vuln.References,
	}

	// Add CVSS details if available
	if vuln.CVSS != nil {
		for source, cvss := range vuln.CVSS {
			if strings.Contains(strings.ToLower(source), "nvd") && cvss.V3Score > 0 {
				tech.CVSS.V3Score = cvss.V3Score
				tech.CVSS.V3Vector = cvss.V3Vector
			} else if cvss.V2Score > 0 {
				tech.CVSS.V2Score = cvss.V2Score
				tech.CVSS.V2Vector = cvss.V2Vector
			}
		}
	}

	// Add dates
	if vuln.PublishedDate != nil {
		tech.PublishedDate = vuln.PublishedDate
	}
	if vuln.LastModifiedDate != nil {
		tech.LastModified = vuln.LastModifiedDate
	}

	// Add layer info for container images
	if vuln.Layer != nil {
		tech.Layer = LayerInfo{
			Digest: vuln.Layer.Digest,
			DiffID: vuln.Layer.DiffID,
		}
	}

	return tech
}

// createMisconfigurationTechnical creates technical details for a misconfiguration.
func (s *Scanner) createMisconfigurationTechnical(misconf TrivyMisconfiguration, result TrivyTargetResult) *TrivyTechnical {
	tech := &TrivyTechnical{
		ScannerType:      "misconfig",
		Target:           result.Target,
		Class:            result.Class,
		CheckID:          misconf.ID,
		CheckTitle:       misconf.Title,
		CheckType:        misconf.Type,
		CheckSeverity:    misconf.Severity,
		CheckDescription: misconf.Description,
		CheckRemediation: misconf.Resolution,
		CheckReferences:  misconf.References,
	}

	// Add line information
	if misconf.CauseMetadata != nil && misconf.CauseMetadata.StartLine > 0 {
		tech.Lines = []LineInfo{
			{
				Start: misconf.CauseMetadata.StartLine,
				End:   misconf.CauseMetadata.EndLine,
			},
		}

		// Add code context if available
		if misconf.CauseMetadata.Code != nil && len(misconf.CauseMetadata.Code.Lines) > 0 {
			var lines []string
			for _, line := range misconf.CauseMetadata.Code.Lines {
				lines = append(lines, line.Content)
			}
			tech.Code = CodeDetails{
				Lines:     lines,
				StartLine: misconf.CauseMetadata.StartLine,
				EndLine:   misconf.CauseMetadata.EndLine,
			}
		}
	}

	return tech
}

// createSecretTechnical creates technical details for a secret.
func (s *Scanner) createSecretTechnical(secret TrivySecret, result TrivyTargetResult) *TrivyTechnical {
	tech := &TrivyTechnical{
		ScannerType: "secret",
		Target:      result.Target,
		Class:       result.Class,
		RuleID:      secret.RuleID,
		Match:       secret.Match,
		SecretType:  secret.Category,
		Lines: []LineInfo{
			{
				Start: secret.StartLine,
				End:   secret.EndLine,
			},
		},
	}

	// Add code context if available
	if len(secret.Code.Lines) > 0 {
		var lines []string
		for _, line := range secret.Code.Lines {
			lines = append(lines, line.Content)
		}
		tech.Code = CodeDetails{
			Lines:     lines,
			StartLine: secret.StartLine,
			EndLine:   secret.EndLine,
		}
	}

	return tech
}

// validateTargets ensures Trivy can handle the requested targets.
func validateTargets(targets scanner.Targets) error {
	if !targets.HasTargets() {
		return scanner.ErrNoTargets
	}

	// Trivy doesn't support direct cloud scanning
	if len(targets.CloudAccounts) > 0 {
		return fmt.Errorf("%w: cloud accounts not supported by trivy", scanner.ErrNotImplemented)
	}

	// Trivy doesn't support web application scanning
	if len(targets.WebApplications) > 0 {
		return fmt.Errorf("%w: web applications not supported by trivy", scanner.ErrNotImplemented)
	}

	return nil
}

// generateFindingID creates a deterministic finding ID.
func generateFindingID(scanner, findingType, resource, identifier, location string) string {
	// Create a unique string from all components
	components := []string{scanner, findingType, resource, identifier, location}
	data := strings.Join(components, "|")

	// Generate SHA256 hash
	hash := sha256.Sum256([]byte(data))

	// Return first 16 characters of hex string for readability
	return hex.EncodeToString(hash[:])[:16]
}

// init registers the Trivy scanner factory with the global registry.
func init() {
	// Register Trivy factory
	if err := scanner.DefaultRegistry.Register(&Factory{}); err != nil {
		// This should never happen unless there's a duplicate registration
		panic(fmt.Sprintf("failed to register Trivy scanner: %v", err))
	}
}
