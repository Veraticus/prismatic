package scanner

import (
	"context"
	"fmt"

	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/joshsymonds/prismatic/pkg/logger"
)

// Scanner defines the interface that all security scanners must implement.
type Scanner interface {
	// Name returns the scanner name (e.g., "prowler", "trivy")
	Name() string

	// Scan executes the scanner and returns raw results
	Scan(ctx context.Context) (*models.ScanResult, error)

	// ParseResults converts raw scanner output to normalized findings
	ParseResults(raw []byte) ([]models.Finding, error)
}

// ProgressReporter is an optional interface that scanners can implement to report progress.
type ProgressReporter interface {
	// SetProgressCallback sets a callback function for progress updates
	SetProgressCallback(callback func(current, total int, message string))
}

// Config holds common scanner configuration.
type Config struct {
	Env        map[string]string
	WorkingDir string
	Timeout    int
	Debug      bool
}

// BaseScanner provides common functionality for all scanners.
type BaseScanner struct {
	logger           logger.Logger
	progressCallback func(current, total int, message string)
	name             string
	version          string
	config           Config
}

// NewBaseScanner creates a new base scanner instance.
func NewBaseScanner(name string, config Config) *BaseScanner {
	return NewBaseScannerWithLogger(name, config, logger.GetGlobalLogger())
}

// NewBaseScannerWithLogger creates a new base scanner instance with a custom logger.
func NewBaseScannerWithLogger(name string, config Config, log logger.Logger) *BaseScanner {
	return &BaseScanner{
		name:   name,
		config: config,
		logger: log,
	}
}

// Name returns the scanner name.
func (b *BaseScanner) Name() string {
	return b.name
}

// GetVersion returns the scanner version.
func (b *BaseScanner) GetVersion() string {
	return b.version
}

// SetVersion sets the scanner version.
func (b *BaseScanner) SetVersion(version string) {
	b.version = version
}

// Config returns the scanner configuration.
func (b *BaseScanner) Config() Config {
	return b.config
}

// ValidateFinding ensures a finding has all required fields.
func ValidateFinding(f *models.Finding) error {
	// Check if severity is provided before normalization
	if f.Severity == "" {
		return fmt.Errorf("invalid finding: severity is required")
	}

	// Normalize severity
	f.Severity = models.NormalizeSeverity(f.Severity)

	if err := f.IsValid(); err != nil {
		return fmt.Errorf("invalid finding: %w", err)
	}

	// Generate ID if not set
	if f.ID == "" {
		f.ID = models.GenerateFindingID(f.Scanner, f.Type, f.Resource, f.Location)
	}

	return nil
}

// SetProgressCallback sets the progress callback function.
func (b *BaseScanner) SetProgressCallback(callback func(current, total int, message string)) {
	b.progressCallback = callback
}

// ReportProgress reports progress if a callback is set.
func (b *BaseScanner) ReportProgress(current, total int, message string) {
	if b.progressCallback != nil {
		b.progressCallback(current, total, message)
	}
}
