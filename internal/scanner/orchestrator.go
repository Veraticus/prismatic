package scanner

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/joshsymonds/prismatic/internal/config"
	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/joshsymonds/prismatic/internal/repository"
	"github.com/joshsymonds/prismatic/pkg/logger"
)

// Orchestrator manages multiple scanners and coordinates their execution.
type Orchestrator struct {
	logger        logger.Logger
	config        *config.Config
	repoPaths     map[string]string
	statusChannel chan *models.ScannerStatus
	outputDir     string
	scanners      []Scanner
	repoCleanups  []func()
	maxWorkers    int
	scanTimeout   time.Duration
	useMock       bool
}

// NewOrchestrator creates a new scanner orchestrator.
func NewOrchestrator(cfg *config.Config, outputDir string, useMock bool) *Orchestrator {
	return NewOrchestratorWithLogger(cfg, outputDir, useMock, logger.GetGlobalLogger())
}

// NewOrchestratorWithLogger creates a new scanner orchestrator with a custom logger.
func NewOrchestratorWithLogger(cfg *config.Config, outputDir string, useMock bool, log logger.Logger) *Orchestrator {
	return &Orchestrator{
		config:       cfg,
		outputDir:    outputDir,
		useMock:      useMock,
		scanners:     []Scanner{},
		maxWorkers:   3, // Default to 3 concurrent scanners
		scanTimeout:  10 * time.Minute,
		logger:       log,
		repoPaths:    make(map[string]string),
		repoCleanups: []func(){},
	}
}

// SetMaxWorkers sets the maximum number of concurrent scanner workers.
func (o *Orchestrator) SetMaxWorkers(maxWorkers int) {
	if maxWorkers < 1 {
		maxWorkers = 1
	}
	o.maxWorkers = maxWorkers
}

// SetScanTimeout sets the timeout for individual scanner execution.
func (o *Orchestrator) SetScanTimeout(timeout time.Duration) {
	o.scanTimeout = timeout
}

// SetStatusChannel sets the channel for receiving scanner status updates.
func (o *Orchestrator) SetStatusChannel(ch chan *models.ScannerStatus) {
	o.statusChannel = ch
}

// PrepareRepositories clones all configured repositories before scanning.
func (o *Orchestrator) PrepareRepositories(ctx context.Context) error {
	if len(o.config.Repositories) == 0 {
		return nil
	}

	o.logger.Info("Preparing repositories", "count", len(o.config.Repositories))

	// Create resolver with repository directory in output
	resolver := repository.NewGitResolver(
		repository.WithBaseDir(filepath.Join(o.outputDir, "repos")),
		repository.WithLogger(o.logger),
	)

	// If mock mode, use mock resolver
	if o.useMock {
		mockPaths := make(map[string]string)
		for _, repo := range o.config.Repositories {
			mockPaths[repo.Name] = filepath.Join(o.outputDir, "mock-repos", repo.Name)
		}
		resolver = repository.NewMockResolver(mockPaths)
	}

	// Clone all repositories
	for _, repo := range o.config.Repositories {
		o.logger.Info("Cloning repository", "name", repo.Name, "url", repo.Path)

		localPath, cleanup, err := resolver(ctx, repo)
		if err != nil {
			o.logger.Error("Repository clone failed", "name", repo.Name, "error", err)
			// Clean up any previously cloned repos
			o.CleanupRepositories()
			return fmt.Errorf("failed to prepare repository %s: %w", repo.Name, err)
		}

		o.repoPaths[repo.Name] = localPath
		o.repoCleanups = append(o.repoCleanups, cleanup)

		o.logger.Info("Repository prepared", "name", repo.Name, "local_path", localPath)
	}

	return nil
}

// CleanupRepositories removes all cloned repositories.
func (o *Orchestrator) CleanupRepositories() {
	for _, cleanup := range o.repoCleanups {
		cleanup()
	}
	o.repoCleanups = []func(){}
	o.repoPaths = make(map[string]string)
}

// GetRepositoryPaths returns the local paths of all prepared repositories.
func (o *Orchestrator) GetRepositoryPaths() map[string]string {
	return o.repoPaths
}

// InitializeScanners sets up scanners based on configuration.
func (o *Orchestrator) InitializeScanners(onlyScanners []string) error {
	baseConfig := Config{
		WorkingDir: o.outputDir,
		Timeout:    300,
		Debug:      false,
	}

	// Create appropriate factory based on mock flag
	var factory interface {
		CreateScanner(string) (Scanner, error)
	}

	if o.useMock {
		factory = NewMockScannerFactory(baseConfig, o.logger)
	} else {
		realFactory := NewScannerFactoryWithLogger(baseConfig, o.config, o.outputDir, o.logger)
		realFactory.SetRepositoryPaths(o.repoPaths)
		factory = realFactory
	}

	// Determine which scanners to initialize
	scannerTypes := o.detectScanners(onlyScanners)

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

	// Send initial pending status for all scanners
	for _, scanner := range o.scanners {
		status := models.NewScannerStatus(scanner.Name())
		o.sendStatus(status)
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

	return metadata, nil
}

// worker processes scanner jobs from the jobs channel.
func (o *Orchestrator) worker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan Scanner, results chan<- *models.ScanResult) {
	defer wg.Done()

	for scanner := range jobs {
		// Send status update if channel is available
		status := models.NewScannerStatus(scanner.Name())
		o.sendStatus(status)

		// Create scanner-specific context with timeout
		scanCtx, cancel := context.WithTimeout(ctx, o.scanTimeout)

		o.logger.Info("Running scanner", "name", scanner.Name())

		// Update status to running
		status.SetRunning("Scanning targets...")
		o.sendStatus(status)

		// Set up progress reporting if scanner supports it
		if reporter, ok := scanner.(ProgressReporter); ok {
			reporter.SetProgressCallback(func(current, total int, message string) {
				status.SetProgress(current, total)
				status.Message = message
				o.sendStatus(status)
			})
		}

		result, err := scanner.Scan(scanCtx)

		cancel() // Clean up the context

		if err != nil {
			if IsNoTargetsError(err) {
				o.logger.Info("Scanner skipped", "name", scanner.Name(), "reason", "No targets configured")
				status.SetSkipped("No targets configured")
				o.sendStatus(status)

				result = &models.ScanResult{
					Scanner:   scanner.Name(),
					StartTime: time.Now(),
					EndTime:   time.Now(),
					Findings:  []models.Finding{},
				}
			} else {
				o.logger.Error("Scanner failed", "name", scanner.Name(), "error", err)
				status.SetFailed(err)
				o.sendStatus(status)

				result = &models.ScanResult{
					Scanner:   scanner.Name(),
					StartTime: time.Now(),
					EndTime:   time.Now(),
					Error:     err.Error(),
					Findings:  []models.Finding{},
				}
			}
		} else {
			// Count findings by severity
			findingCounts := make(map[string]int)
			totalFindings := len(result.Findings)

			for _, finding := range result.Findings {
				if !finding.Suppressed {
					findingCounts[finding.Severity]++
				}
			}

			status.SetCompletedWithFindings(totalFindings, findingCounts)
			o.sendStatus(status)
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
			// Use WithSeverity to normalize the override
			finding.WithSeverity(newSeverity)
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
// It modifies findings in-place rather than creating new objects.

// getScannerNames returns the names of all configured scanners.
func (o *Orchestrator) getScannerNames() []string {
	names := make([]string, len(o.scanners))
	for i, scanner := range o.scanners {
		names[i] = scanner.Name()
	}
	return names
}

// detectScanners determines which scanners to use based on configuration.
func (o *Orchestrator) detectScanners(onlyScanners []string) []string {
	// If specific scanners requested, use only those (but still check if enabled)
	if len(onlyScanners) > 0 {
		return o.filterEnabledScanners(onlyScanners)
	}

	// Otherwise, determine based on configuration
	var scanners []string

	// Check AWS config
	if o.config.AWS != nil && len(o.config.AWS.Profiles) > 0 {
		scanners = append(scanners, "prowler")
	}

	// Check Docker config
	if o.config.Docker != nil && len(o.config.Docker.Containers) > 0 {
		scanners = append(scanners, "trivy")
	}

	// Check Kubernetes config
	if o.config.Kubernetes != nil && len(o.config.Kubernetes.Contexts) > 0 {
		scanners = append(scanners, "kubescape")
	}

	// Check endpoints
	if len(o.config.Endpoints) > 0 {
		scanners = append(scanners, "nuclei")
	}

	// Always include these scanners if not filtered
	scanners = append(scanners, "gitleaks", "checkov")

	return o.filterEnabledScanners(scanners)
}

// filterEnabledScanners filters out disabled scanners based on configuration.
func (o *Orchestrator) filterEnabledScanners(scanners []string) []string {
	// If no scanner configuration, all scanners are enabled by default
	if o.config.Scanners == nil {
		return scanners
	}

	enabled := make([]string, 0, len(scanners))
	for _, scanner := range scanners {
		// Check if scanner has explicit configuration
		if scannerConfig, exists := o.config.Scanners[scanner]; exists {
			// Skip if explicitly disabled
			if !scannerConfig.Enabled {
				o.logger.Debug("Scanner disabled by configuration", "scanner", scanner)
				continue
			}
		}
		// If no explicit config or enabled=true, include the scanner
		enabled = append(enabled, scanner)
	}

	return enabled
}

// sendStatus sends a status update if the status channel is available.
func (o *Orchestrator) sendStatus(status *models.ScannerStatus) {
	if o.statusChannel != nil {
		select {
		case o.statusChannel <- status:
		default:
			// Don't block if channel is full
		}
	}
}
