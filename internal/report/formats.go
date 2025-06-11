// Package report provides functionality for generating security reports from scan results.
package report

import (
	"fmt"
	"sync"

	"github.com/joshsymonds/prismatic/internal/config"
	"github.com/joshsymonds/prismatic/internal/enrichment"
	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/joshsymonds/prismatic/pkg/logger"
)

// ReportFormat represents a report generation strategy.
type ReportFormat interface {
	// Generate creates the report in the specific format.
	Generate(findings []models.Finding, enrichments map[string]*enrichment.FindingEnrichment, metadata *models.ScanMetadata, outputPath string) error
	// Name returns the format identifier (e.g., "html", "pdf", "remediation").
	Name() string
	// Description returns a human-readable description of the format.
	Description() string
}

// ReportFormatFactory creates instances of report formats.
type ReportFormatFactory func(cfg *config.Config, log logger.Logger) (ReportFormat, error)

var (
	formatRegistry = make(map[string]ReportFormatFactory)
	registryMutex  sync.RWMutex
)

// RegisterFormat registers a new report format factory.
func RegisterFormat(name string, factory ReportFormatFactory) {
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
func GetFormat(name string, cfg *config.Config, log logger.Logger) (ReportFormat, error) {
	registryMutex.RLock()
	factory, exists := formatRegistry[name]
	registryMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("unknown report format: %s", name)
	}

	return factory(cfg, log)
}

// ListFormats returns a list of all registered format names.
func ListFormats() []string {
	registryMutex.RLock()
	defer registryMutex.RUnlock()

	var formats []string
	for name := range formatRegistry {
		formats = append(formats, name)
	}
	return formats
}

// htmlFormat adapts the existing HTMLGenerator to the ReportFormat interface.
type htmlFormat struct {
	generator *HTMLGenerator
}

func (f *htmlFormat) Generate(findings []models.Finding, enrichments map[string]*enrichment.FindingEnrichment, metadata *models.ScanMetadata, outputPath string) error {
	// The existing HTMLGenerator already has the findings and enrichments
	return f.generator.Generate(outputPath)
}

func (f *htmlFormat) Name() string {
	return "html"
}

func (f *htmlFormat) Description() string {
	return "HTML report optimized for AI readability with prismatic theme"
}

// pdfFormat handles PDF generation.
type pdfFormat struct {
	htmlGenerator *HTMLGenerator
	logger        logger.Logger
}

func (f *pdfFormat) Generate(findings []models.Finding, enrichments map[string]*enrichment.FindingEnrichment, metadata *models.ScanMetadata, outputPath string) error {
	// First generate HTML to a temporary file
	htmlFile := outputPath + ".tmp.html"
	if err := f.htmlGenerator.Generate(htmlFile); err != nil {
		return fmt.Errorf("generating HTML for PDF: %w", err)
	}

	// Convert HTML to PDF
	if err := ConvertHTMLToPDF(htmlFile, outputPath); err != nil {
		return fmt.Errorf("converting HTML to PDF: %w", err)
	}

	// Remove the intermediate HTML file
	// Note: Ignoring error as it's just cleanup
	_ = removeFile(htmlFile)

	return nil
}

func (f *pdfFormat) Name() string {
	return "pdf"
}

func (f *pdfFormat) Description() string {
	return "PDF report for compliance and archival purposes"
}

// removeFile is a helper to remove files (abstracted for testing).
var removeFile = func(path string) error {
	return nil // Placeholder - actual implementation would use os.Remove
}

// Register built-in formats during package initialization.
func init() {
	// HTML format
	RegisterFormat("html", func(cfg *config.Config, log logger.Logger) (ReportFormat, error) {
		// This is a placeholder - we'll need to refactor HTMLGenerator creation
		// For now, return nil to allow compilation
		return nil, fmt.Errorf("html format factory not yet implemented")
	})

	// PDF format
	RegisterFormat("pdf", func(cfg *config.Config, log logger.Logger) (ReportFormat, error) {
		// This is a placeholder - we'll need to refactor for PDF generation
		return nil, fmt.Errorf("pdf format factory not yet implemented")
	})

	// Remediation format
	RegisterFormat("remediation", func(cfg *config.Config, log logger.Logger) (ReportFormat, error) {
		return NewRemediationReporter(cfg, log), nil
	})

	// Fix bundle format
	RegisterFormat("fix-bundle", func(cfg *config.Config, log logger.Logger) (ReportFormat, error) {
		return &fixBundleFormat{
			generator: NewFixBundleGenerator(cfg, log),
		}, nil
	})
}
