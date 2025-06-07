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
	config    *config.Config
	outputDir string
	scanners  []Scanner
	useMock   bool
}

// NewOrchestrator creates a new scanner orchestrator.
func NewOrchestrator(cfg *config.Config, outputDir string, useMock bool) *Orchestrator {
	return &Orchestrator{
		config:    cfg,
		outputDir: outputDir,
		useMock:   useMock,
		scanners:  []Scanner{},
	}
}

// InitializeScanners sets up scanners based on configuration.
func (o *Orchestrator) InitializeScanners(onlyScanners []string) error {
	baseConfig := Config{
		WorkingDir: o.outputDir,
		Timeout:    300,
		Debug:      false,
	}

	// Determine which scanners to initialize
	scannerTypes := o.determineScanners(onlyScanners)

	// Initialize appropriate scanners
	for _, scannerType := range scannerTypes {
		var scanner Scanner

		if o.useMock {
			scanner = NewMockScanner(scannerType, baseConfig)
		} else {
			// Initialize real scanners
			switch scannerType {
			case "trivy":
				targets := o.getTrivyTargets()
				if len(targets) == 0 {
					logger.Warn("No targets configured for Trivy")
					continue
				}
				scanner = NewTrivyScanner(baseConfig, targets)
			case "prowler":
				profiles, regions, services := o.getProwlerConfig()
				if len(profiles) == 0 {
					logger.Warn("No AWS profiles configured for Prowler")
					continue
				}
				scanner = NewProwlerScanner(baseConfig, profiles, regions, services)
			case "kubescape":
				contexts, namespaces := o.getKubescapeConfig()
				if len(contexts) == 0 {
					logger.Warn("No Kubernetes contexts configured for Kubescape")
					continue
				}
				scanner = NewKubescapeScanner(baseConfig, contexts, namespaces)
			case "nuclei":
				endpoints := o.config.Endpoints
				if len(endpoints) == 0 {
					logger.Warn("No endpoints configured for Nuclei")
					continue
				}
				scanner = NewNucleiScanner(baseConfig, endpoints)
			case "gitleaks":
				scanner = NewGitleaksScanner(baseConfig, o.getGitleaksTarget())
			case "checkov":
				targets := o.getCheckovTargets()
				if len(targets) == 0 {
					logger.Warn("No targets configured for Checkov")
					continue
				}
				scanner = NewCheckovScanner(baseConfig, targets)
			default:
				logger.Warn("Unknown scanner type", "scanner", scannerType)
				continue
			}
		}

		o.scanners = append(o.scanners, scanner)
		logger.Debug("Initialized scanner", "name", scanner.Name(), "type", scannerType)
	}

	if len(o.scanners) == 0 {
		return fmt.Errorf("no scanners initialized")
	}

	return nil
}

// determineScanners returns which scanner types to use based on config and filters.
func (o *Orchestrator) determineScanners(onlyScanners []string) []string {
	var scanners []string

	// If specific scanners requested, use only those
	if len(onlyScanners) > 0 {
		return onlyScanners
	}

	// Otherwise, determine based on configuration
	if o.config.AWS != nil && len(o.config.AWS.Profiles) > 0 {
		scanners = append(scanners, "prowler")
	}

	if o.config.Docker != nil && len(o.config.Docker.Containers) > 0 {
		scanners = append(scanners, "trivy")
	}

	if o.config.Kubernetes != nil && len(o.config.Kubernetes.Contexts) > 0 {
		scanners = append(scanners, "kubescape")
	}

	if len(o.config.Endpoints) > 0 {
		scanners = append(scanners, "nuclei")
	}

	// Always include these if not filtered
	scanners = append(scanners, "gitleaks", "checkov")

	return scanners
}

// RunScans executes all scanners in parallel.
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

	// Channel for results
	resultsChan := make(chan *models.ScanResult, len(o.scanners))
	var wg sync.WaitGroup

	// Run scanners in parallel
	for _, scanner := range o.scanners {
		wg.Add(1)
		go func(s Scanner) {
			defer wg.Done()

			logger.Info("Running scanner", "name", s.Name())
			result, err := s.Scan(ctx)

			if err != nil {
				logger.Error("Scanner failed", "name", s.Name(), "error", err)
				result = &models.ScanResult{
					Scanner:   s.Name(),
					StartTime: time.Now(),
					EndTime:   time.Now(),
					Error:     err.Error(),
					Findings:  []models.Finding{},
				}
				metadata.Summary.FailedScanners = append(metadata.Summary.FailedScanners, s.Name())
			}

			resultsChan <- result
		}(scanner)
	}

	// Wait for all scanners and close channel
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect results
	for result := range resultsChan {
		o.processResult(result, metadata)
	}

	metadata.EndTime = time.Now()
	metadata.Scanners = o.getScannerNames()

	return metadata, nil
}

// processResult processes a single scanner result and updates metadata.
func (o *Orchestrator) processResult(result *models.ScanResult, metadata *models.ScanMetadata) {
	// Apply suppressions and severity overrides
	var processedFindings []models.Finding

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
			logger.Warn("Invalid finding skipped",
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
}

// EnrichFindings adds business context to findings if metadata enrichment is configured.
// This is an optional post-processing step that runs after all scanners complete.
func (o *Orchestrator) EnrichFindings(metadata *models.ScanMetadata) []models.EnrichedFinding {
	var enrichedFindings []models.EnrichedFinding

	// If no metadata enrichment is configured, return empty slice (not an error)
	if o.config.MetadataEnrichment.Resources == nil || len(o.config.MetadataEnrichment.Resources) == 0 {
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

				logger.Debug("Enriched finding with business context",
					"resource", finding.Resource,
					"owner", resourceMetadata.Owner,
				)
			}

			enrichedFindings = append(enrichedFindings, *enrichedFinding)
		}
	}

	logger.Info("Completed finding enrichment",
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

	// Add current directory for filesystem scanning if no specific targets
	if len(targets) == 0 {
		targets = append(targets, ".")
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
