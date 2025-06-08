package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Veraticus/prismatic/internal/config"
	"github.com/Veraticus/prismatic/internal/models"
	"github.com/Veraticus/prismatic/pkg/logger"
)

// Orchestrator manages multiple scanners and coordinates their execution.
type Orchestrator struct {
	logger      logger.Logger
	config      *config.Config
	outputDir   string
	scanners    []Scanner
	maxWorkers  int
	scanTimeout time.Duration
	useMock     bool
}

// NewOrchestrator creates a new scanner orchestrator.
func NewOrchestrator(cfg *config.Config, outputDir string, useMock bool) *Orchestrator {
	return NewOrchestratorWithLogger(cfg, outputDir, useMock, logger.GetGlobalLogger())
}

// NewOrchestratorWithLogger creates a new scanner orchestrator with a custom logger.
func NewOrchestratorWithLogger(cfg *config.Config, outputDir string, useMock bool, log logger.Logger) *Orchestrator {
	return &Orchestrator{
		config:      cfg,
		outputDir:   outputDir,
		useMock:     useMock,
		scanners:    []Scanner{},
		maxWorkers:  3, // Default to 3 concurrent scanners
		scanTimeout: 10 * time.Minute,
		logger:      log,
	}
}

// SetMaxWorkers sets the maximum number of concurrent scanner workers.
func (o *Orchestrator) SetMaxWorkers(max int) {
	if max < 1 {
		max = 1
	}
	o.maxWorkers = max
}

// SetScanTimeout sets the timeout for individual scanner execution.
func (o *Orchestrator) SetScanTimeout(timeout time.Duration) {
	o.scanTimeout = timeout
}

// InitializeScanners sets up scanners based on configuration.
func (o *Orchestrator) InitializeScanners(onlyScanners []string) error {
	baseConfig := Config{
		WorkingDir: o.outputDir,
		Timeout:    300,
		Debug:      false,
	}

	// Create scanner factory
	factory := NewScannerFactoryWithLogger(baseConfig, o, o.outputDir, o.useMock, o.logger)

	// Determine which scanners to initialize
	detector := NewScannerTypeDetector(o)
	scannerTypes := detector.DetectScanners(onlyScanners)

	// Initialize scanners using factory
	for _, scannerType := range scannerTypes {
		scanner, err := factory.CreateScanner(scannerType)
		if err != nil {
			// Skip scanners that can't be initialized (e.g., no config)
			o.logger.Debug("Skipping scanner", "type", scannerType, "reason", err)
			continue
		}

		o.scanners = append(o.scanners, scanner)
		o.logger.Debug("Initialized scanner", "name", scanner.Name(), "type", scannerType)
	}

	if len(o.scanners) == 0 {
		return fmt.Errorf("no scanners initialized")
	}

	return nil
}

// RunScans executes all scanners with resource management using worker pool.
func (o *Orchestrator) RunScans(ctx context.Context) (*models.ScanMetadata, error) {
	metadata := &models.ScanMetadata{
		StartTime:   time.Now(),
		ClientName:  o.config.Client.Name,
		Environment: o.config.Client.Environment,
		Results:     make(map[string]*models.ScanResult),
		Summary: models.ScanSummary{
			BySeverity: make(map[string]int),
			ByScanner:  make(map[string]int),
		},
	}

	// Create worker pool
	jobs := make(chan Scanner, len(o.scanners))
	results := make(chan *models.ScanResult, len(o.scanners))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < o.maxWorkers && i < len(o.scanners); i++ {
		wg.Add(1)
		go o.worker(ctx, &wg, jobs, results)
	}

	// Send jobs to workers
	go func() {
		for _, scanner := range o.scanners {
			select {
			case jobs <- scanner:
			case <-ctx.Done():
				close(jobs)
				return
			}
		}
		close(jobs)
	}()

	// Wait for workers to finish and close results
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	for result := range results {
		o.processResult(result, metadata)
	}

	metadata.EndTime = time.Now()
	metadata.Scanners = o.getScannerNames()

	// Enrich findings with business context if configured
	enrichedFindings := o.EnrichFindings(metadata)
	if len(enrichedFindings) > 0 {
		metadata.EnrichedFindings = enrichedFindings
		o.logger.Info("Enriched findings with business context", "count", len(enrichedFindings))
	}

	return metadata, nil
}

// worker processes scanner jobs from the jobs channel.
func (o *Orchestrator) worker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan Scanner, results chan<- *models.ScanResult) {
	defer wg.Done()

	for scanner := range jobs {
		// Create scanner-specific context with timeout
		scanCtx, cancel := context.WithTimeout(ctx, o.scanTimeout)

		o.logger.Info("Running scanner", "name", scanner.Name())
		result, err := scanner.Scan(scanCtx)

		cancel() // Clean up the context

		if err != nil {
			o.logger.Error("Scanner failed", "name", scanner.Name(), "error", err)
			result = &models.ScanResult{
				Scanner:   scanner.Name(),
				StartTime: time.Now(),
				EndTime:   time.Now(),
				Error:     err.Error(),
				Findings:  []models.Finding{},
			}
		}

		select {
		case results <- result:
		case <-ctx.Done():
			return
		}
	}
}

// processResult processes a single scanner result and updates metadata.
func (o *Orchestrator) processResult(result *models.ScanResult, metadata *models.ScanMetadata) {
	// Apply suppressions and severity overrides
	processedFindings := make([]models.Finding, 0, len(result.Findings))

	for _, finding := range result.Findings {
		// Check if suppressed using the finding's discovered date
		// Use PublishedDate for CVEs if available, otherwise use DiscoveredDate
		suppressionDate := finding.DiscoveredDate
		if !finding.PublishedDate.IsZero() && finding.Type == "vulnerability" {
			suppressionDate = finding.PublishedDate
		}

		suppressed, reason := o.config.IsSuppressed(finding.Scanner, finding.Type, suppressionDate)
		if suppressed {
			finding.Suppressed = true
			finding.SuppressionReason = reason
			metadata.Summary.SuppressedCount++
		}

		// Apply severity override
		if newSeverity, ok := o.config.GetSeverityOverride(finding.Type); ok {
			finding.OriginalSeverity = finding.Severity
			finding.Severity = models.NormalizeSeverity(newSeverity)
		}

		// Validate and normalize
		if err := ValidateFinding(&finding); err != nil {
			o.logger.Warn("Invalid finding skipped",
				"scanner", finding.Scanner,
				"type", finding.Type,
				"error", err,
			)
			continue
		}

		processedFindings = append(processedFindings, finding)

		// Update summary
		if !finding.Suppressed {
			metadata.Summary.TotalFindings++
			metadata.Summary.BySeverity[finding.Severity]++
		}
	}

	result.Findings = processedFindings
	metadata.Results[result.Scanner] = result
	metadata.Summary.ByScanner[result.Scanner] = len(processedFindings)

	// Track failed scanners
	if result.Error != "" {
		metadata.Summary.FailedScanners = append(metadata.Summary.FailedScanners, result.Scanner)
	}
}

// EnrichFindings adds business context to findings if metadata enrichment is configured.
// This is an optional post-processing step that runs after all scanners complete.
func (o *Orchestrator) EnrichFindings(metadata *models.ScanMetadata) []models.EnrichedFinding {
	var enrichedFindings []models.EnrichedFinding

	// If no metadata enrichment is configured, return empty slice (not an error)
	if len(o.config.MetadataEnrichment.Resources) == 0 {
		return enrichedFindings
	}

	// Process each scanner's results
	for _, result := range metadata.Results {
		for _, finding := range result.Findings {
			// Create base enriched finding
			enrichedFinding := models.EnrichFinding(finding)

			// Try to match resource metadata
			if resourceMetadata, ok := o.config.GetResourceMetadata(finding.Resource); ok {
				businessContext := models.BusinessContext{
					Owner:              resourceMetadata.Owner,
					DataClassification: resourceMetadata.DataClassification,
					BusinessImpact:     resourceMetadata.BusinessImpact,
					ComplianceImpact:   resourceMetadata.ComplianceImpact,
				}
				enrichedFinding.SetBusinessContext(businessContext)

				o.logger.Debug("Enriched finding with business context",
					"resource", finding.Resource,
					"owner", resourceMetadata.Owner,
				)
			}

			enrichedFindings = append(enrichedFindings, *enrichedFinding)
		}
	}

	o.logger.Info("Completed finding enrichment",
		"total_findings", len(enrichedFindings),
		"resources_with_metadata", len(o.config.MetadataEnrichment.Resources),
	)

	return enrichedFindings
}

// getScannerNames returns the names of all configured scanners.
func (o *Orchestrator) getScannerNames() []string {
	names := make([]string, len(o.scanners))
	for i, scanner := range o.scanners {
		names[i] = scanner.Name()
	}
	return names
}

// getTrivyTargets returns targets for Trivy scanning based on configuration.
func (o *Orchestrator) getTrivyTargets() []string {
	var targets []string

	// Add Docker containers
	if o.config.Docker != nil {
		targets = append(targets, o.config.Docker.Containers...)
	}

	return targets
}

// getGitleaksTarget returns the target path for Gitleaks scanning.
func (o *Orchestrator) getGitleaksTarget() string {
	// For now, always scan the current directory
	// In the future, this could be configurable
	return "."
}

// getProwlerConfig returns Prowler configuration from the main config.
func (o *Orchestrator) getProwlerConfig() (profiles, regions, services []string) {
	if o.config.AWS == nil {
		return nil, nil, nil
	}

	// Get profiles
	profiles = o.config.AWS.Profiles

	// Get regions
	regions = o.config.AWS.Regions

	// Get services if specified
	// For now, we'll scan all services unless specified
	// This could be extended to read from config
	services = []string{}

	return profiles, regions, services
}

// getKubescapeConfig returns Kubescape configuration from the main config.
func (o *Orchestrator) getKubescapeConfig() (contexts, namespaces []string) {
	if o.config.Kubernetes == nil {
		return nil, nil
	}

	contexts = o.config.Kubernetes.Contexts
	namespaces = o.config.Kubernetes.Namespaces

	return contexts, namespaces
}

// getCheckovTargets returns target directories for Checkov IaC scanning.
func (o *Orchestrator) getCheckovTargets() []string {
	// Checkov scans Infrastructure-as-Code files in directories
	// For now, scan the current directory and any terraform/kubernetes directories
	targets := []string{"."}

	// Could be extended to read from config.IaC.Directories or similar
	// For now, return current directory which will scan all IaC files recursively
	return targets
}

// ClientConfig interface implementation

// GetAWSConfig returns AWS configuration for scanners.
func (o *Orchestrator) GetAWSConfig() (profiles []string, regions []string, services []string) {
	return o.getProwlerConfig()
}

// GetDockerTargets returns Docker targets for scanners.
func (o *Orchestrator) GetDockerTargets() []string {
	return o.getTrivyTargets()
}

// GetKubernetesConfig returns Kubernetes configuration for scanners.
func (o *Orchestrator) GetKubernetesConfig() (contexts []string, namespaces []string) {
	return o.getKubescapeConfig()
}

// GetEndpoints returns web endpoints for scanners.
func (o *Orchestrator) GetEndpoints() []string {
	return o.config.Endpoints
}

// GetCheckovTargets returns targets for Checkov scanner.
func (o *Orchestrator) GetCheckovTargets() []string {
	return o.getCheckovTargets()
}
