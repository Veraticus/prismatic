// Package scanner provides adapters for integrating scanners with storage and processing.
package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/joshsymonds/prismatic/internal/database"
	"github.com/joshsymonds/prismatic/internal/models"
)

// ErrNilFinding is returned when a nil finding is passed to a processor.
var ErrNilFinding = errors.New("finding is nil")

// ErrFindingSuppressed is returned when a finding is suppressed and should be dropped.
var ErrFindingSuppressed = errors.New("finding is suppressed")

// ErrDuplicateFinding is returned when a finding is a duplicate and should be dropped.
var ErrDuplicateFinding = errors.New("duplicate finding")

// DatabaseStore adapts the database package to the FindingStore interface.
// It is thread-safe and can be used concurrently.
type DatabaseStore struct {
	db     *database.DB
	scanID int64
}

// NewDatabaseStore creates a new database-backed finding store.
func NewDatabaseStore(db *database.DB, scanID int64) *DatabaseStore {
	if db == nil {
		panic("database is nil")
	}
	return &DatabaseStore{
		db:     db,
		scanID: scanID,
	}
}

// Store persists findings to the database.
func (s *DatabaseStore) Store(ctx context.Context, findings []*models.Finding) error {
	if len(findings) == 0 {
		return nil
	}

	// Convert to database findings
	dbFindings := make([]*database.Finding, 0, len(findings))

	for _, f := range findings {
		// Skip nil findings
		if f == nil {
			continue
		}

		dbFinding := &database.Finding{
			ScanID:      s.scanID,
			Scanner:     f.Scanner,
			Severity:    s.normalizeSeverity(f.Severity),
			Title:       f.Title,
			Description: f.Description,
			Resource:    f.Resource,
		}

		// Build technical details JSON including all extra fields
		technicalDetails := make(map[string]any)
		technicalDetails["type"] = f.Type
		technicalDetails["remediation"] = f.Remediation

		// Add metadata
		for k, v := range f.Metadata {
			technicalDetails[k] = v
		}

		// Add business context if present
		if f.BusinessContext != nil {
			technicalDetails["business_impact"] = f.BusinessContext.BusinessImpact
			technicalDetails["owner"] = f.BusinessContext.Owner
			technicalDetails["data_classification"] = f.BusinessContext.DataClassification
			technicalDetails["compliance_impact"] = f.BusinessContext.ComplianceImpact
		}

		// Convert to JSON
		if detailsJSON, err := json.Marshal(technicalDetails); err == nil {
			dbFinding.TechnicalDetails = detailsJSON
		}

		dbFindings = append(dbFindings, dbFinding)
	}

	if len(dbFindings) == 0 {
		return nil
	}

	return s.db.BatchInsertFindings(ctx, s.scanID, dbFindings)
}

// normalizeSeverity maps model severity to database severity.
// The database uses uppercase, models use lowercase.
func (s *DatabaseStore) normalizeSeverity(severity string) database.Severity {
	switch strings.ToLower(severity) {
	case "critical":
		return database.SeverityCritical
	case "high":
		return database.SeverityHigh
	case "medium":
		return database.SeverityMedium
	case "low":
		return database.SeverityLow
	case "info", "informational":
		return database.SeverityInfo
	default:
		// Unknown severities default to info
		return database.SeverityInfo
	}
}

// SeverityNormalizer normalizes severity values across scanners.
// Different scanners use different severity naming conventions.
type SeverityNormalizer struct{}

// NewSeverityNormalizer creates a new severity normalizer.
func NewSeverityNormalizer() *SeverityNormalizer {
	return &SeverityNormalizer{}
}

// Process normalizes the severity field of a finding.
func (n *SeverityNormalizer) Process(_ context.Context, finding *models.Finding) (*models.Finding, error) {
	if finding == nil {
		return nil, ErrNilFinding
	}
	finding.Severity = models.NormalizeSeverity(finding.Severity)
	return finding, nil
}

// Name returns the processor name.
func (n *SeverityNormalizer) Name() string {
	return "severity-normalizer"
}

// SuppressionsFilter filters out suppressed findings based on rules.
type SuppressionsFilter struct {
	suppressions map[string]bool
}

// NewSuppressionsFilter creates a filter with the given suppression rules.
func NewSuppressionsFilter(suppressions []string) *SuppressionsFilter {
	filter := &SuppressionsFilter{
		suppressions: make(map[string]bool, len(suppressions)),
	}
	for _, id := range suppressions {
		filter.suppressions[id] = true
	}
	return filter
}

// Process filters out suppressed findings.
// Returns nil to drop the finding from processing.
func (f *SuppressionsFilter) Process(_ context.Context, finding *models.Finding) (*models.Finding, error) {
	if finding == nil {
		return nil, ErrNilFinding
	}

	// Check if finding is suppressed
	if f.suppressions[finding.ID] {
		// Drop the finding by returning nil
		return nil, ErrFindingSuppressed
	}

	// Check patterns (simplified - in real implementation, support wildcards)
	for pattern := range f.suppressions {
		if strings.Contains(finding.ID, pattern) {
			return nil, ErrFindingSuppressed
		}
	}

	return finding, nil
}

// Name returns the processor name.
func (f *SuppressionsFilter) Name() string {
	return "suppressions-filter"
}

// MetadataEnricher adds business context to findings.
type MetadataEnricher struct {
	metadata map[string]models.BusinessContext
}

// NewMetadataEnricher creates an enricher with business metadata.
func NewMetadataEnricher(metadata map[string]models.BusinessContext) *MetadataEnricher {
	return &MetadataEnricher{
		metadata: metadata,
	}
}

// Process enriches findings with business context based on resource.
func (e *MetadataEnricher) Process(_ context.Context, finding *models.Finding) (*models.Finding, error) {
	if finding == nil {
		return nil, ErrNilFinding
	}

	// Look up business context by resource
	if context, exists := e.metadata[finding.Resource]; exists {
		// Clone the context to avoid sharing
		finding.BusinessContext = &models.BusinessContext{
			Owner:              context.Owner,
			DataClassification: context.DataClassification,
			BusinessImpact:     context.BusinessImpact,
			ComplianceImpact:   context.ComplianceImpact,
		}
	}

	return finding, nil
}

// Name returns the processor name.
func (e *MetadataEnricher) Name() string {
	return "metadata-enricher"
}

// SeverityOverrideProcessor applies severity overrides based on rules.
type SeverityOverrideProcessor struct {
	overrides map[string]string // finding pattern -> new severity
}

// NewSeverityOverrideProcessor creates a processor with override rules.
func NewSeverityOverrideProcessor(overrides map[string]string) *SeverityOverrideProcessor {
	return &SeverityOverrideProcessor{
		overrides: overrides,
	}
}

// Process applies severity overrides to findings.
func (p *SeverityOverrideProcessor) Process(_ context.Context, finding *models.Finding) (*models.Finding, error) {
	if finding == nil {
		return nil, ErrNilFinding
	}

	// Check for exact match
	if newSeverity, exists := p.overrides[finding.ID]; exists {
		finding.Severity = newSeverity
		finding.Metadata["severity_overridden"] = "true"
		finding.Metadata["original_severity"] = finding.Severity
	}

	// Check patterns (simplified)
	for pattern, newSeverity := range p.overrides {
		if strings.Contains(finding.ID, pattern) || strings.Contains(finding.Type, pattern) {
			finding.Metadata["severity_overridden"] = "true"
			finding.Metadata["original_severity"] = finding.Severity
			finding.Severity = newSeverity
			break
		}
	}

	return finding, nil
}

// Name returns the processor name.
func (p *SeverityOverrideProcessor) Name() string {
	return "severity-override"
}

// DeduplicationProcessor removes duplicate findings.
type DeduplicationProcessor struct {
	seen map[string]bool
}

// NewDeduplicationProcessor creates a processor that removes duplicates.
func NewDeduplicationProcessor() *DeduplicationProcessor {
	return &DeduplicationProcessor{
		seen: make(map[string]bool),
	}
}

// Process drops duplicate findings based on ID.
func (d *DeduplicationProcessor) Process(_ context.Context, finding *models.Finding) (*models.Finding, error) {
	if finding == nil {
		return nil, ErrNilFinding
	}

	// Check if we've seen this finding
	if d.seen[finding.ID] {
		// Drop duplicate
		return nil, ErrDuplicateFinding
	}

	// Mark as seen
	d.seen[finding.ID] = true
	return finding, nil
}

// Name returns the processor name.
func (d *DeduplicationProcessor) Name() string {
	return "deduplication"
}

// ChainProcessor chains multiple processors together.
type ChainProcessor struct {
	name       string
	processors []FindingProcessor
}

// NewChainProcessor creates a processor that chains multiple processors.
func NewChainProcessor(name string, processors ...FindingProcessor) *ChainProcessor {
	return &ChainProcessor{
		processors: processors,
		name:       name,
	}
}

// Process runs the finding through all processors in order.
func (c *ChainProcessor) Process(ctx context.Context, finding *models.Finding) (*models.Finding, error) {
	if finding == nil {
		return nil, ErrNilFinding
	}

	var err error
	for _, processor := range c.processors {
		finding, err = processor.Process(ctx, finding)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", processor.Name(), err)
		}

		// If any processor returns nil with an error like suppression/deduplication,
		// the error was already returned above. If nil without error, it's a bug.
		if finding == nil {
			return nil, fmt.Errorf("processor %s returned nil finding without error", processor.Name())
		}
	}

	return finding, nil
}

// Name returns the processor name.
func (c *ChainProcessor) Name() string {
	return c.name
}
