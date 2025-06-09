// Package scanner provides a base implementation for security scanners.
//
// The SimpleScan method provides a template implementation that handles:
// - Context cancellation
// - Error handling and logging
// - Finding validation
// - Progress tracking
//
// Example usage:
//
//	func (s *MyScanner) Scan(ctx context.Context) (*models.ScanResult, error) {
//	    iterator := NewSimpleTargetIterator(s.targets, func(t string) string {
//	        return fmt.Sprintf("target-%s", t)
//	    })
//
//	    return s.BaseScanner.SimpleScan(ctx, SimpleScanOptions{
//	        ScannerName:     s.Name(),
//	        GetVersion:      s.getVersion,
//	        Iterator:        iterator,
//	        ScanTarget:      s.scanSingleTarget,
//	        ParseOutput:     s.ParseResults,
//	        ContinueOnError: true,
//	    })
//	}
package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/Veraticus/prismatic/internal/models"
)

// ScanFunc is a function that performs the actual scan for a specific target.
type ScanFunc func(ctx context.Context, target string) ([]byte, error)

// ParseFunc is a function that parses raw scanner output into findings.
type ParseFunc func(raw []byte) ([]models.Finding, error)

// TargetIterator provides targets to scan.
type TargetIterator interface {
	// Targets returns the list of targets to scan.
	Targets() []string
	// TargetDescription returns a human-readable description for logging.
	TargetDescription(target string) string
}

// SimpleScanOptions provides options for the simple scan template.
type SimpleScanOptions struct {
	Iterator        TargetIterator
	GetVersion      func(ctx context.Context) string
	ScanTarget      ScanFunc
	ParseOutput     ParseFunc
	ScannerName     string
	ContinueOnError bool
}

// SimpleScan provides a common scan implementation that most scanners can use.
func (b *BaseScanner) SimpleScan(ctx context.Context, opts SimpleScanOptions) (*models.ScanResult, error) {
	startTime := time.Now()

	result := &models.ScanResult{
		Scanner:   opts.ScannerName,
		Version:   opts.GetVersion(ctx),
		StartTime: startTime,
		Findings:  []models.Finding{},
	}

	targets := opts.Iterator.Targets()
	if len(targets) == 0 {
		b.logger.Warn("No targets to scan", "scanner", opts.ScannerName)
		result.EndTime = time.Now()
		return result, nil
	}

	for i, target := range targets {
		// Check for context cancellation
		if err := ctx.Err(); err != nil {
			result.EndTime = time.Now()
			result.Error = fmt.Sprintf("scan canceled: %v", err)
			b.logger.Info("Scan canceled", "scanner", opts.ScannerName, "target", target)
			return result, nil
		}

		targetDesc := opts.Iterator.TargetDescription(target)
		b.logger.Debug("Scanning target", "scanner", opts.ScannerName, "target", targetDesc)

		// Report progress
		b.ReportProgress(i+1, len(targets), fmt.Sprintf("Scanning %s", targetDesc))

		// Run the scan
		output, err := opts.ScanTarget(ctx, target)
		if err != nil {
			b.logger.Error("Failed to scan target",
				"scanner", opts.ScannerName,
				"target", targetDesc,
				"error", err)
			if !opts.ContinueOnError {
				result.EndTime = time.Now()
				result.Error = fmt.Sprintf("scan failed for %s: %v", targetDesc, err)
				return result, fmt.Errorf("scanning %s: %w", targetDesc, err)
			}
			continue
		}

		// Parse results
		findings, err := opts.ParseOutput(output)
		if err != nil {
			b.logger.Error("Failed to parse results",
				"scanner", opts.ScannerName,
				"target", targetDesc,
				"error", err)
			if !opts.ContinueOnError {
				result.EndTime = time.Now()
				result.Error = fmt.Sprintf("parse failed for %s: %v", targetDesc, err)
				return result, fmt.Errorf("parsing results for %s: %w", targetDesc, err)
			}
			continue
		}

		// Validate findings before adding
		validFindings := make([]models.Finding, 0, len(findings))
		for _, finding := range findings {
			if err := ValidateFinding(&finding); err != nil {
				b.logger.Warn("Invalid finding skipped",
					"scanner", opts.ScannerName,
					"type", finding.Type,
					"error", err)
				continue
			}
			validFindings = append(validFindings, finding)
		}

		result.Findings = append(result.Findings, validFindings...)
		b.logger.Info("Completed scanning target",
			"scanner", opts.ScannerName,
			"target", targetDesc,
			"findings", len(validFindings))
	}

	result.EndTime = time.Now()
	b.logger.Info("Scan completed",
		"scanner", opts.ScannerName,
		"duration", result.EndTime.Sub(result.StartTime),
		"total_findings", len(result.Findings))

	return result, nil
}

// SimpleTargetIterator provides a basic implementation of TargetIterator.
type SimpleTargetIterator struct {
	description func(string) string
	targets     []string
}

// NewSimpleTargetIterator creates a new SimpleTargetIterator.
func NewSimpleTargetIterator(targets []string, description func(string) string) *SimpleTargetIterator {
	if description == nil {
		description = func(t string) string { return t }
	}
	return &SimpleTargetIterator{
		targets:     targets,
		description: description,
	}
}

// Targets returns the list of targets.
func (s *SimpleTargetIterator) Targets() []string {
	return s.targets
}

// TargetDescription returns a description of the target.
func (s *SimpleTargetIterator) TargetDescription(target string) string {
	return s.description(target)
}
