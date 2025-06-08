package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/Veraticus/prismatic/internal/models"
	"github.com/Veraticus/prismatic/pkg/logger"
)

// ScannerExecutor provides common execution patterns for scanners.
type ScannerExecutor struct {
	timeout time.Duration
}

// NewScannerExecutor creates a new scanner executor with the given timeout.
func NewScannerExecutor(timeout time.Duration) *ScannerExecutor {
	return &ScannerExecutor{
		timeout: timeout,
	}
}

// Execute runs a scanner with common pre/post processing and error handling.
func (e *ScannerExecutor) Execute(ctx context.Context, scanner Scanner, execFunc func(context.Context) (*models.ScanResult, error)) (*models.ScanResult, error) {
	// Create scanner-specific context with timeout
	scanCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	// Initialize result
	result := &models.ScanResult{
		Scanner:   scanner.Name(),
		StartTime: time.Now(),
		Findings:  []models.Finding{},
	}

	// Check if context is already canceled
	if err := scanCtx.Err(); err != nil {
		result.EndTime = time.Now()
		result.Error = fmt.Sprintf("scan canceled before starting: %v", err)
		return result, nil
	}

	// Execute the scanner-specific logic
	execResult, err := execFunc(scanCtx)

	// Handle cancellation
	if scanCtx.Err() != nil {
		result.EndTime = time.Now()
		result.Error = fmt.Sprintf("scan canceled: %v", scanCtx.Err())
		return result, nil
	}

	// Handle execution errors
	if err != nil {
		result.EndTime = time.Now()
		result.Error = err.Error()
		logger.Error("Scanner failed", "scanner", scanner.Name(), "error", err)
		return result, err
	}

	// Use the execution result if successful
	if execResult != nil {
		result = execResult
	}

	// Ensure end time is set
	if result.EndTime.IsZero() {
		result.EndTime = time.Now()
	}

	return result, nil
}

// ExecuteCommand provides a common pattern for command-based scanners.
type CommandExecutor struct {
	ParseFunc func([]byte) ([]models.Finding, error)
	Scanner   string
}

// ProcessOutput processes command output and parses findings.
func (ce *CommandExecutor) ProcessOutput(output []byte, result *models.ScanResult) error {
	if len(output) == 0 {
		logger.Debug("No output from scanner", "scanner", ce.Scanner)
		return nil
	}

	result.RawOutput = output

	findings, err := ce.ParseFunc(output)
	if err != nil {
		logger.Warn("Failed to parse results", "scanner", ce.Scanner, "error", err)
		return fmt.Errorf("parsing results: %w", err)
	}

	result.Findings = findings
	return nil
}

// MultiTargetExecutor helps scanners that process multiple targets.
type MultiTargetExecutor struct {
	ParseFunc func([]byte) ([]models.Finding, error)
	Scanner   string
}

// ProcessTargets processes multiple targets and aggregates findings.
func (mte *MultiTargetExecutor) ProcessTargets(targets []string, execFunc func(string) ([]byte, error), result *models.ScanResult) {
	for _, target := range targets {
		logger.Debug("Processing target", "scanner", mte.Scanner, "target", target)

		output, err := execFunc(target)
		if err != nil {
			logger.Warn("Failed to scan target",
				"scanner", mte.Scanner,
				"target", target,
				"error", err)
			continue
		}

		if len(output) == 0 {
			continue
		}

		findings, err := mte.ParseFunc(output)
		if err != nil {
			logger.Debug("Failed to parse results for target",
				"scanner", mte.Scanner,
				"target", target,
				"error", err)
			continue
		}

		result.Findings = append(result.Findings, findings...)
	}
}
