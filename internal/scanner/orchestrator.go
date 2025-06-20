// Package scanner provides orchestration for security scanners.
package scanner

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/joshsymonds/prismatic/pkg/logger"
)

// FindingProcessor processes findings before storage.
// Processors can transform, enrich, or filter findings.
// Returning nil drops the finding from processing.
type FindingProcessor interface {
	Process(ctx context.Context, finding *models.Finding) (*models.Finding, error)
	Name() string // For debugging and metrics
}

// FindingStore persists findings.
type FindingStore interface {
	Store(ctx context.Context, findings []*models.Finding) error
}

// OrchestratorConfig configures the scan orchestrator.
type OrchestratorConfig struct {
	Logger        logger.Logger
	Store         FindingStore
	Progress      ProgressFunc
	Processors    []FindingProcessor
	MaxConcurrent int
	BatchSize     int
	BatchTimeout  time.Duration
}

// scannerFinding wraps a finding with its source scanner name.
type scannerFinding struct {
	finding Finding
	scanner string
}

// SetDefaults applies sensible defaults to config.
func (c *OrchestratorConfig) SetDefaults() {
	if c.MaxConcurrent <= 0 {
		c.MaxConcurrent = 3
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 100
	}
	if c.BatchTimeout <= 0 {
		c.BatchTimeout = 5 * time.Second
	}
	if c.Logger == nil {
		c.Logger = logger.GetGlobalLogger()
	}
}

// Orchestrator coordinates multiple scanner executions.
// It handles concurrent scanning, finding processing, and storage.
type Orchestrator struct {
	scanners map[string]Scanner
	cancel   context.CancelFunc
	config   OrchestratorConfig
	mu       sync.RWMutex
	running  atomic.Bool
}

// NewOrchestrator creates a new scan orchestrator.
func NewOrchestrator(config OrchestratorConfig) *Orchestrator {
	config.SetDefaults()

	return &Orchestrator{
		config:   config,
		scanners: make(map[string]Scanner),
	}
}

// AddScanner adds a scanner to be executed.
// Returns error if a scanner with the same name already exists.
func (o *Orchestrator) AddScanner(scanner Scanner) error {
	if scanner == nil {
		return fmt.Errorf("scanner is nil")
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	name := scanner.Name()
	if _, exists := o.scanners[name]; exists {
		return fmt.Errorf("scanner already added: %s", name)
	}

	o.scanners[name] = scanner
	return nil
}

// RemoveScanner removes a scanner by name.
func (o *Orchestrator) RemoveScanner(name string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.scanners, name)
}

// Execute runs all configured scanners and returns results.
// It blocks until all scanners complete or context is canceled.
func (o *Orchestrator) Execute(ctx context.Context) (*ScanResult, error) {
	// Check if already running
	if !o.running.CompareAndSwap(false, true) {
		return nil, ErrScanInProgress
	}
	defer o.running.Store(false)

	// Get scanner snapshot
	o.mu.RLock()
	if len(o.scanners) == 0 {
		o.mu.RUnlock()
		return nil, fmt.Errorf("no scanners configured")
	}

	// Copy scanners to avoid holding lock during execution
	scanners := make(map[string]Scanner, len(o.scanners))
	for name, scanner := range o.scanners {
		scanners[name] = scanner
	}
	o.mu.RUnlock()

	// Create cancellable context
	ctx, cancel := context.WithCancel(ctx)
	o.cancel = cancel
	defer cancel()

	// Initialize result
	result := &ScanResult{
		StartTime:     time.Now(),
		FindingCounts: make(map[string]int),
		Errors:        make(map[string]error),
	}

	// Create channels
	findingsChan := make(chan scannerFinding, o.config.BatchSize)

	// Start processor goroutine
	processorDone := make(chan struct{})
	go o.processFindings(ctx, findingsChan, result, processorDone)

	// Run scanners concurrently
	var wg sync.WaitGroup
	sem := make(chan struct{}, o.config.MaxConcurrent)

	for name, scanner := range scanners {
		wg.Add(1)
		go func(name string, scanner Scanner) {
			defer wg.Done()

			// Rate limit
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			// Report progress
			if o.config.Progress != nil {
				o.config.Progress(Progress{
					Scanner: name,
					Phase:   "starting",
					Message: fmt.Sprintf("Starting %s scanner", name),
				})
			}

			// Run scanner
			if err := o.runScanner(ctx, name, scanner, findingsChan); err != nil {
				result.mu.Lock()
				result.Errors[name] = err
				result.mu.Unlock()

				o.config.Logger.Error("Scanner failed",
					"scanner", name,
					"error", err)
			}

			// Report completion
			if o.config.Progress != nil {
				o.config.Progress(Progress{
					Scanner: name,
					Phase:   "completed",
					Message: fmt.Sprintf("%s scanner completed", name),
				})
			}
		}(name, scanner)
	}

	// Wait for all scanners
	wg.Wait()
	close(findingsChan)

	// Wait for processor
	<-processorDone

	result.EndTime = time.Now()
	return result, nil
}

// Stop gracefully stops the orchestrator.
func (o *Orchestrator) Stop() {
	if o.cancel != nil {
		o.cancel()
	}
}

// runScanner executes a single scanner and streams findings.
func (o *Orchestrator) runScanner(ctx context.Context, name string, scanner Scanner, out chan<- scannerFinding) error {
	// Ensure scanner is closed
	defer func() {
		if err := scanner.Close(); err != nil {
			o.config.Logger.Error("Failed to close scanner",
				"scanner", name,
				"error", err)
		}
	}()

	// Start scan
	findings, err := scanner.Scan(ctx)
	if err != nil {
		return fmt.Errorf("scan start failed: %w", err)
	}

	// Stream findings
	count := 0
	for finding := range findings {
		count++

		// Attach scanner name to finding
		if finding.Finding != nil {
			finding.Finding.Scanner = name
		}

		select {
		case out <- scannerFinding{scanner: name, finding: finding}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	o.config.Logger.Info("Scanner completed",
		"scanner", name,
		"findings", count)

	return nil
}

// processFindings handles finding processing and storage.
func (o *Orchestrator) processFindings(ctx context.Context, findings <-chan scannerFinding, result *ScanResult, done chan<- struct{}) {
	defer close(done)

	batch := make([]*models.Finding, 0, o.config.BatchSize)
	ticker := time.NewTicker(o.config.BatchTimeout)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}

		// Process findings through pipeline
		processed := make([]*models.Finding, 0, len(batch))

		for _, finding := range batch {
			f := finding

			// Run through processors
			for _, processor := range o.config.Processors {
				select {
				case <-ctx.Done():
					return
				default:
				}

				var err error
				f, err = processor.Process(ctx, f)
				if err != nil {
					o.config.Logger.Error("Processor failed",
						"processor", processor.Name(),
						"finding", finding.ID,
						"error", err)
					// Continue with original finding
					f = finding
				}

				// Processor can drop findings by returning nil
				if f == nil {
					break
				}
			}

			if f != nil {
				processed = append(processed, f)
			}
		}

		// Store processed findings
		if len(processed) > 0 && o.config.Store != nil {
			if err := o.config.Store.Store(ctx, processed); err != nil {
				o.config.Logger.Error("Storage failed",
					"count", len(processed),
					"error", err)
			}
		}

		// Update result counts
		result.mu.Lock()
		for _, f := range processed {
			result.FindingCounts[f.Scanner]++
			result.TotalFindings++

			// Track by severity
			if result.BySeverity == nil {
				result.BySeverity = make(map[string]int)
			}
			result.BySeverity[f.Severity]++

			// Track by type
			if result.ByType == nil {
				result.ByType = make(map[string]int)
			}
			result.ByType[f.Type]++
		}
		result.mu.Unlock()

		// Clear batch
		batch = batch[:0]
	}

	// Process findings
	for {
		select {
		case sf, ok := <-findings:
			if !ok {
				flush()
				return
			}

			// Handle errors
			if sf.finding.Error != nil {
				result.mu.Lock()
				if result.ScannerErrors == nil {
					result.ScannerErrors = make(map[string][]error)
				}
				result.ScannerErrors[sf.scanner] = append(
					result.ScannerErrors[sf.scanner],
					sf.finding.Error,
				)
				result.mu.Unlock()
				continue
			}

			// Add to batch
			if sf.finding.Finding != nil {
				batch = append(batch, sf.finding.Finding)
				if len(batch) >= o.config.BatchSize {
					flush()
				}
			}

		case <-ticker.C:
			flush()

		case <-ctx.Done():
			flush()
			return
		}
	}
}

// ScanResult contains the results of an orchestrated scan.
type ScanResult struct {
	StartTime     time.Time
	EndTime       time.Time
	FindingCounts map[string]int
	BySeverity    map[string]int
	ByType        map[string]int
	Errors        map[string]error
	ScannerErrors map[string][]error
	TotalFindings int
	mu            sync.Mutex
}

// Duration returns how long the scan took.
func (r *ScanResult) Duration() time.Duration {
	return r.EndTime.Sub(r.StartTime)
}

// Success returns true if all scanners completed without errors.
func (r *ScanResult) Success() bool {
	return len(r.Errors) == 0 && len(r.ScannerErrors) == 0
}

// Summary generates a human-readable summary.
func (r *ScanResult) Summary() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	summary := fmt.Sprintf(
		"Scan completed in %s\n"+
			"Total findings: %d\n"+
			"Scanners: %d\n",
		r.Duration().Round(time.Second),
		r.TotalFindings,
		len(r.FindingCounts),
	)

	// Add severity breakdown
	if len(r.BySeverity) > 0 {
		summary += "\nBy Severity:\n"
		for sev, count := range r.BySeverity {
			summary += fmt.Sprintf("  %s: %d\n", sev, count)
		}
	}

	// Add scanner breakdown
	if len(r.FindingCounts) > 0 {
		summary += "\nBy Scanner:\n"
		for scanner, count := range r.FindingCounts {
			summary += fmt.Sprintf("  %s: %d", scanner, count)
			if err, ok := r.Errors[scanner]; ok {
				summary += fmt.Sprintf(" (failed: %v)", err)
			}
			summary += "\n"
		}
	}

	return summary
}
