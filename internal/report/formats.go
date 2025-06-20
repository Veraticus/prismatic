// Package report provides functionality for generating security reports from scan results.
package report

import (
	"fmt"
	"sync"

	"github.com/joshsymonds/prismatic/internal/database"
	"github.com/joshsymonds/prismatic/internal/enrichment"
	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/joshsymonds/prismatic/internal/storage"
	"github.com/joshsymonds/prismatic/pkg/logger"
)

// Format represents a report generation strategy.
type Format interface {
	// Generate creates the report in the specific format.
	Generate(findings []models.Finding, enrichments map[string]*enrichment.FindingEnrichment, metadata *models.ScanMetadata, outputPath string) error
	// Name returns the format identifier (e.g., "html", "pdf", "remediation").
	Name() string
	// Description returns a human-readable description of the format.
	Description() string
}

// FormatFactory creates instances of report formats.
type FormatFactory func(log logger.Logger) (Format, error)

var (
	formatRegistry = make(map[string]FormatFactory)
	registryMutex  sync.RWMutex
)

// RegisterFormat registers a new report format factory.
func RegisterFormat(name string, factory FormatFactory) {
	registryMutex.Lock()
	defer registryMutex.Unlock()

	if factory == nil {
		panic(fmt.Sprintf("report: RegisterFormat factory is nil for format %q", name))
	}
	if _, dup := formatRegistry[name]; dup {
		panic(fmt.Sprintf("report: RegisterFormat called twice for format %q", name))
	}
	formatRegistry[name] = factory
}

// GetFormat creates an instance of the specified report format.
func GetFormat(name string, log logger.Logger) (Format, error) {
	registryMutex.RLock()
	factory, exists := formatRegistry[name]
	registryMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("unknown report format: %s", name)
	}

	return factory(log)
}

// ListFormats returns a list of all registered format names.
func ListFormats() []string {
	registryMutex.RLock()
	defer registryMutex.RUnlock()

	formats := make([]string, 0, len(formatRegistry))
	for name := range formatRegistry {
		formats = append(formats, name)
	}
	return formats
}

// htmlFormat adapts HTMLGenerator to the Format interface.
type htmlFormat struct {
	logger logger.Logger
}

// Generate creates an HTML report.
func (f *htmlFormat) Generate(findings []models.Finding, enrichments map[string]*enrichment.FindingEnrichment, metadata *models.ScanMetadata, outputPath string) error {
	// Create a temporary database to store the findings
	db, err := database.New(":memory:")
	if err != nil {
		return fmt.Errorf("creating database: %w", err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			f.logger.Warn("failed to close database", "error", closeErr)
		}
	}()

	// Create storage
	store := storage.NewStorageWithLogger(db, f.logger)

	// Create a fake scan ID
	scanID := int64(1)

	// Save scan results to database
	if saveErr := store.SaveScanResults(scanID, metadata); saveErr != nil {
		return fmt.Errorf("saving scan results: %w", saveErr)
	}

	// Create HTML generator
	gen, err := NewHTMLGeneratorWithDatabase(fmt.Sprintf("%d", scanID), db, f.logger)
	if err != nil {
		return fmt.Errorf("creating HTML generator: %w", err)
	}

	// Override the findings in the generator
	gen.findings = findings
	gen.enrichments = enrichments

	// Generate the report
	return gen.Generate(outputPath)
}

// Name returns the format identifier.
func (f *htmlFormat) Name() string {
	return "html"
}

// Description returns a human-readable description.
func (f *htmlFormat) Description() string {
	return "HTML report with interactive features and AI enrichments"
}

// Register built-in formats during package initialization.
func init() {
	// HTML format
	RegisterFormat("html", func(log logger.Logger) (Format, error) {
		// Return a wrapper that implements the Format interface
		return &htmlFormat{logger: log}, nil
	})

	// PDF format
	RegisterFormat("pdf", func(_ logger.Logger) (Format, error) {
		// This is a placeholder - we'll need to refactor for PDF generation
		return nil, fmt.Errorf("pdf format factory not yet implemented")
	})

	// Remediation format
	RegisterFormat("remediation", func(log logger.Logger) (Format, error) {
		return NewRemediationReporter(log), nil
	})

	// Fix bundle format
	RegisterFormat("fix-bundle", func(log logger.Logger) (Format, error) {
		return &fixBundleFormat{
			generator: NewFixBundleGenerator(log),
		}, nil
	})
}
