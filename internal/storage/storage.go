// Package storage handles persistence of scan results and findings.
package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/joshsymonds/prismatic/internal/database"
	"github.com/joshsymonds/prismatic/internal/enrichment"
	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/joshsymonds/prismatic/pkg/logger"
)

// Storage handles saving and loading scan results using the database.
type Storage struct {
	logger logger.Logger
	db     *database.DB
}

// NewStorage creates a new storage instance backed by database.
func NewStorage(db *database.DB) *Storage {
	return NewStorageWithLogger(db, logger.GetGlobalLogger())
}

// NewStorageWithLogger creates a new storage instance with a custom logger.
func NewStorageWithLogger(db *database.DB, log logger.Logger) *Storage {
	if db == nil {
		panic("database is nil")
	}
	return &Storage{
		db:     db,
		logger: log,
	}
}

// SaveScanResults saves scan results to the database.
func (s *Storage) SaveScanResults(scanID int64, metadata *models.ScanMetadata) error {
	ctx := context.Background()

	// Save scan metadata
	dbMetadata := &database.ScanMetadata{
		ScanID:      scanID,
		ClientName:  sql.NullString{String: metadata.ClientName, Valid: metadata.ClientName != ""},
		Environment: sql.NullString{String: metadata.Environment, Valid: metadata.Environment != ""},
	}

	// Marshal summary to JSON
	if summaryJSON, err := json.Marshal(metadata.Summary); err == nil {
		dbMetadata.Summary = summaryJSON
	}

	// Marshal scanner versions if available
	versions := make(map[string]string)
	for scanner, result := range metadata.Results {
		if result.Version != "" {
			versions[scanner] = result.Version
		}
	}
	if len(versions) > 0 {
		if versionsJSON, err := json.Marshal(versions); err == nil {
			dbMetadata.ScannerVersions = versionsJSON
		}
	}

	if err := s.db.SaveScanMetadata(ctx, dbMetadata); err != nil {
		return fmt.Errorf("saving scan metadata: %w", err)
	}
	s.logger.Debug("Saved scan metadata", "scanID", scanID)

	// Save raw scanner outputs
	for scanner, result := range metadata.Results {
		if len(result.RawOutput) > 0 {
			if err := s.db.SaveScannerOutput(ctx, scanID, scanner, string(result.RawOutput)); err != nil {
				s.logger.Warn("Failed to save raw output", "scanner", scanner, "error", err)
			} else {
				s.logger.Debug("Saved raw output", "scanner", scanner)
			}
		}

		// Update scanner progress to completed/failed
		progress := &database.ScanProgress{
			ScanID:          scanID,
			Scanner:         scanner,
			Status:          "completed",
			ProgressPercent: 100,
		}
		if result.Error != "" {
			progress.Status = "failed"
			progress.ErrorMessage = sql.NullString{String: result.Error, Valid: true}
		}
		if err := s.db.UpdateScanProgress(ctx, progress); err != nil {
			s.logger.Warn("Failed to update scanner progress", "scanner", scanner, "error", err)
		}
	}

	// Save human-readable scan log
	s.saveScanLog(ctx, scanID, metadata)

	return nil
}

// LoadScanResults loads scan results from the database.
func (s *Storage) LoadScanResults(scanID int64) (*models.ScanMetadata, error) {
	ctx := context.Background()

	// Load scan record
	scan, err := s.db.GetScan(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("loading scan: %w", err)
	}

	// Load scan metadata
	dbMetadata, err := s.db.GetScanMetadata(ctx, scanID)
	if err != nil {
		if errors.Is(err, database.ErrNoMetadata) {
			// Return empty metadata if none found
			return &models.ScanMetadata{
				ID:        fmt.Sprintf("scan-%d", scanID),
				StartTime: scan.StartedAt,
				EndTime:   scan.CompletedAt.Time,
				Results:   make(map[string]*models.ScanResult),
			}, nil
		}
		return nil, fmt.Errorf("loading scan metadata: %w", err)
	}

	// Build ScanMetadata
	metadata := &models.ScanMetadata{
		ClientName:  dbMetadata.ClientName.String,
		Environment: dbMetadata.Environment.String,
		StartTime:   scan.StartedAt,
	}

	if scan.CompletedAt.Valid {
		metadata.EndTime = scan.CompletedAt.Time
	}

	// Unmarshal summary
	if len(dbMetadata.Summary) > 0 {
		if unmarshalErr := json.Unmarshal(dbMetadata.Summary, &metadata.Summary); unmarshalErr != nil {
			s.logger.Warn("Failed to unmarshal summary", "error", unmarshalErr)
		}
	}

	// Initialize Results map
	metadata.Results = make(map[string]*models.ScanResult)

	// Load scan progress to get all scanners that ran
	progress, err := s.db.GetScanProgress(ctx, scanID)
	if err != nil {
		s.logger.Warn("Failed to load scan progress", "error", err)
	} else {
		for _, p := range progress {
			if _, ok := metadata.Results[p.Scanner]; !ok {
				metadata.Results[p.Scanner] = &models.ScanResult{
					Scanner: p.Scanner,
				}
				metadata.Scanners = append(metadata.Scanners, p.Scanner)
			}
			// Set error if scanner failed
			if p.Status == "failed" && p.ErrorMessage.Valid {
				metadata.Results[p.Scanner].Error = p.ErrorMessage.String
			}
		}
	}

	// Load scanner outputs
	outputs, err := s.db.GetScannerOutputs(ctx, scanID)
	if err != nil {
		s.logger.Warn("Failed to load scanner outputs", "error", err)
	} else {
		for _, output := range outputs {
			if result, ok := metadata.Results[output.Scanner]; ok {
				result.RawOutput = []byte(output.RawOutput)
			}
		}
	}

	// Sort scanners list
	sort.Strings(metadata.Scanners)

	// Load findings for each scanner
	findings, err := s.db.GetFindings(ctx, scanID, database.FindingFilter{})
	if err != nil {
		s.logger.Warn("Failed to load findings", "error", err)
	} else {
		// Group findings by scanner
		for _, dbFinding := range findings {
			if result, ok := metadata.Results[dbFinding.Scanner]; ok {
				finding := s.convertDBFindingToModel(dbFinding)
				result.Findings = append(result.Findings, finding)
			}
		}
	}

	return metadata, nil
}

// FindLatestScan finds the most recent scan ID.
func (s *Storage) FindLatestScan() (int64, error) {
	ctx := context.Background()

	scans, err := s.db.ListScans(ctx, database.ScanFilter{
		Limit: 1,
	})
	if err != nil {
		return 0, fmt.Errorf("listing scans: %w", err)
	}

	if len(scans) == 0 {
		return 0, fmt.Errorf("no scans found")
	}

	return scans[0].ID, nil
}

// ListScans returns a list of available scans.
func (s *Storage) ListScans(client string, limit int) ([]ScanInfo, error) {
	ctx := context.Background()

	filter := database.ScanFilter{
		Limit: limit,
	}
	if client != "" {
		filter.AWSProfile = &client
	}

	scans, err := s.db.ListScans(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("listing scans: %w", err)
	}

	scanInfos := make([]ScanInfo, 0, len(scans))
	for _, scan := range scans {
		// Load metadata for each scan
		metadata, err := s.db.GetScanMetadata(ctx, scan.ID)
		if err != nil {
			s.logger.Debug("Failed to load metadata for scan", "scanID", scan.ID, "error", err)
			continue
		}

		// Load finding counts
		counts, err := s.db.GetFindingCounts(ctx, scan.ID)
		if err != nil {
			s.logger.Debug("Failed to load finding counts", "scanID", scan.ID, "error", err)
		}

		info := ScanInfo{
			ID:          fmt.Sprintf("%d", scan.ID),
			ClientName:  metadata.ClientName.String,
			Environment: metadata.Environment.String,
			StartTime:   scan.StartedAt,
		}

		if scan.CompletedAt.Valid {
			info.EndTime = scan.CompletedAt.Time
		}

		// Build summary from counts
		if counts != nil {
			info.Summary = models.ScanSummary{
				TotalFindings: counts.Total,
				BySeverity: map[string]int{
					"critical": counts.Critical,
					"high":     counts.High,
					"medium":   counts.Medium,
					"low":      counts.Low,
					"info":     counts.Info,
				},
			}
		}

		scanInfos = append(scanInfos, info)
	}

	return scanInfos, nil
}

// ScanInfo provides summary information about a scan.
type ScanInfo struct {
	ID          string
	Path        string // Deprecated, kept for compatibility
	ClientName  string
	Environment string
	StartTime   time.Time
	EndTime     time.Time
	Summary     models.ScanSummary
}

// LoadEnrichments loads AI enrichments from the database.
func (s *Storage) LoadEnrichments(scanID int64) ([]enrichment.FindingEnrichment, *enrichment.Metadata, error) {
	ctx := context.Background()

	dbEnrichments, err := s.db.GetFindingEnrichments(ctx, scanID)
	if err != nil {
		return nil, nil, fmt.Errorf("loading enrichments: %w", err)
	}

	enrichments := make([]enrichment.FindingEnrichment, 0, len(dbEnrichments))
	for _, dbEnrich := range dbEnrichments {
		enrich := enrichment.FindingEnrichment{
			FindingID:  dbEnrich.FindingID,
			EnrichedAt: dbEnrich.CreatedAt,
		}

		// Build analysis from database fields
		enrich.Analysis = enrichment.Analysis{
			BusinessImpact: dbEnrich.BusinessImpact.String,
		}

		// Build remediation
		var remediation enrichment.Remediation
		if dbEnrich.EstimatedEffort.Valid {
			remediation.EstimatedEffort = dbEnrich.EstimatedEffort.String
		}
		enrich.Remediation = remediation

		// Unmarshal AI analysis if present for additional fields
		if len(dbEnrich.AIAnalysis) > 0 {
			var aiData map[string]any
			if err := json.Unmarshal(dbEnrich.AIAnalysis, &aiData); err == nil {
				// Extract additional analysis fields
				if priority, ok := aiData["priority_score"].(float64); ok {
					enrich.Analysis.PriorityScore = priority
				}
				if reasoning, ok := aiData["priority_reasoning"].(string); ok {
					enrich.Analysis.PriorityReasoning = reasoning
				}
				if technical, ok := aiData["technical_details"].(string); ok {
					enrich.Analysis.TechnicalDetails = technical
				}
				if contextual, ok := aiData["contextual_notes"].(string); ok {
					enrich.Analysis.ContextualNotes = contextual
				}
				// Extract remediation steps
				if immediate, ok := aiData["immediate_steps"].([]any); ok {
					for _, step := range immediate {
						if s, ok := step.(string); ok {
							enrich.Remediation.Immediate = append(enrich.Remediation.Immediate, s)
						}
					}
				}
				if shortTerm, ok := aiData["short_term_steps"].([]any); ok {
					for _, step := range shortTerm {
						if s, ok := step.(string); ok {
							enrich.Remediation.ShortTerm = append(enrich.Remediation.ShortTerm, s)
						}
					}
				}
				if longTerm, ok := aiData["long_term_steps"].([]any); ok {
					for _, step := range longTerm {
						if s, ok := step.(string); ok {
							enrich.Remediation.LongTerm = append(enrich.Remediation.LongTerm, s)
						}
					}
				}
			}
		}

		enrichments = append(enrichments, enrich)
	}

	// Build metadata
	var metadata *enrichment.Metadata
	if len(enrichments) > 0 {
		metadata = &enrichment.Metadata{
			StartedAt:        dbEnrichments[0].CreatedAt,
			CompletedAt:      dbEnrichments[len(dbEnrichments)-1].CreatedAt,
			TotalFindings:    len(enrichments),
			EnrichedFindings: len(enrichments),
		}

		// Extract enrichment metadata from first enrichment's AI analysis
		if len(dbEnrichments) > 0 && len(dbEnrichments[0].AIAnalysis) > 0 {
			var aiData map[string]any
			if err := json.Unmarshal(dbEnrichments[0].AIAnalysis, &aiData); err == nil {
				if enrichMeta, ok := aiData["enrichment_metadata"].(map[string]any); ok {
					if strategy, ok := enrichMeta["strategy"].(string); ok {
						metadata.Strategy = strategy
					}
					if driver, ok := enrichMeta["driver"].(string); ok {
						metadata.Driver = driver
					}
				}
			}
		}
	}

	if metadata != nil {
		s.logger.Debug("Loaded enrichments", "count", len(enrichments), "strategy", metadata.Strategy, "driver", metadata.Driver)
	} else {
		s.logger.Debug("Loaded enrichments", "count", 0)
	}
	return enrichments, metadata, nil
}

// SaveEnrichments saves AI enrichments to the database.
func (s *Storage) SaveEnrichments(scanID int64, enrichments []enrichment.FindingEnrichment, metadata *enrichment.Metadata) error {
	ctx := context.Background()

	// Store metadata in the first enrichment's AI analysis if metadata is provided
	var metadataMap map[string]any
	if metadata != nil {
		metadataMap = map[string]any{
			"strategy": metadata.Strategy,
			"driver":   metadata.Driver,
		}
	}

	for i, enrich := range enrichments {
		dbEnrich := &database.FindingEnrichment{
			FindingID:       enrich.FindingID,
			ScanID:          scanID,
			BusinessImpact:  sql.NullString{String: enrich.Analysis.BusinessImpact, Valid: enrich.Analysis.BusinessImpact != ""},
			EstimatedEffort: sql.NullString{String: enrich.Remediation.EstimatedEffort, Valid: enrich.Remediation.EstimatedEffort != ""},
		}

		// Combine remediation steps
		if len(enrich.Remediation.Immediate) > 0 || len(enrich.Remediation.ShortTerm) > 0 || len(enrich.Remediation.LongTerm) > 0 {
			var steps []string
			steps = append(steps, enrich.Remediation.Immediate...)
			steps = append(steps, enrich.Remediation.ShortTerm...)
			steps = append(steps, enrich.Remediation.LongTerm...)
			if len(steps) > 0 {
				dbEnrich.RemediationSteps = sql.NullString{String: strings.Join(steps, "; "), Valid: true}
			}
		}

		// Set risk score based on priority score
		if enrich.Analysis.PriorityScore > 0 {
			dbEnrich.RiskScore = sql.NullInt64{Int64: int64(enrich.Analysis.PriorityScore * 100), Valid: true}
		}

		// Marshal the entire analysis as AI analysis
		aiData := map[string]any{
			"priority_score":     enrich.Analysis.PriorityScore,
			"priority_reasoning": enrich.Analysis.PriorityReasoning,
			"technical_details":  enrich.Analysis.TechnicalDetails,
			"contextual_notes":   enrich.Analysis.ContextualNotes,
			"related_findings":   enrich.Analysis.RelatedFindings,
			"dependencies":       enrich.Analysis.Dependencies,
			"immediate_steps":    enrich.Remediation.Immediate,
			"short_term_steps":   enrich.Remediation.ShortTerm,
			"long_term_steps":    enrich.Remediation.LongTerm,
			"llm_model":          enrich.LLMModel,
			"tokens_used":        enrich.TokensUsed,
		}

		// Store metadata in first enrichment
		if i == 0 && metadataMap != nil {
			aiData["enrichment_metadata"] = metadataMap
		}

		if analysisJSON, err := json.Marshal(aiData); err == nil {
			dbEnrich.AIAnalysis = analysisJSON
		}

		if err := s.db.SaveFindingEnrichment(ctx, dbEnrich); err != nil {
			s.logger.Warn("Failed to save enrichment", "finding_id", enrich.FindingID, "error", err)
			continue
		}
	}

	s.logger.Debug("Saved enrichments", "count", len(enrichments))
	return nil
}

// GetScanDirectory returns empty string as we no longer use directories.
func (s *Storage) GetScanDirectory() string {
	return ""
}

// LoadResults loads results for a specific scanner from the current scan.
func (s *Storage) LoadResults(scanID int64, scanner string) (*models.ScanResult, error) {
	ctx := context.Background()

	// Load findings for the scanner
	scannerFilter := scanner
	findings, err := s.db.GetFindings(ctx, scanID, database.FindingFilter{
		Scanner: &scannerFilter,
	})
	if err != nil {
		return nil, fmt.Errorf("loading findings: %w", err)
	}

	result := &models.ScanResult{
		Scanner: scanner,
	}

	// Convert findings
	for _, dbFinding := range findings {
		finding := s.convertDBFindingToModel(dbFinding)
		result.Findings = append(result.Findings, finding)
	}

	// Load raw output if available
	outputs, err := s.db.GetScannerOutputs(ctx, scanID)
	if err == nil {
		for _, output := range outputs {
			if output.Scanner == scanner {
				result.RawOutput = []byte(output.RawOutput)
				break
			}
		}
	}

	return result, nil
}

// saveScanLog saves a human-readable scan log to the database.
func (s *Storage) saveScanLog(ctx context.Context, scanID int64, metadata *models.ScanMetadata) {
	// Log scan start
	if err := s.db.SaveScanLog(ctx, &database.ScanLog{
		ScanID:   scanID,
		LogLevel: "INFO",
		Message:  fmt.Sprintf("Prismatic Security Scan started for %s (%s)", metadata.ClientName, metadata.Environment),
	}); err != nil {
		s.logger.Debug("Failed to save scan log", "error", err)
	}

	// Log scanner results
	for _, scanner := range metadata.Scanners {
		if result, ok := metadata.Results[scanner]; ok {
			if result.Error != "" {
				if err := s.db.SaveScanLog(ctx, &database.ScanLog{
					ScanID:   scanID,
					LogLevel: "ERROR",
					Message:  fmt.Sprintf("Scanner %s failed: %s", scanner, result.Error),
					Scanner:  sql.NullString{String: scanner, Valid: true},
				}); err != nil {
					s.logger.Debug("Failed to save scan log", "error", err)
				}
			} else {
				if err := s.db.SaveScanLog(ctx, &database.ScanLog{
					ScanID:   scanID,
					LogLevel: "INFO",
					Message:  fmt.Sprintf("Scanner %s completed: %d findings", scanner, len(result.Findings)),
					Scanner:  sql.NullString{String: scanner, Valid: true},
				}); err != nil {
					s.logger.Debug("Failed to save scan log", "error", err)
				}
			}
		}
	}

	// Log summary
	if err := s.db.SaveScanLog(ctx, &database.ScanLog{
		ScanID:   scanID,
		LogLevel: "INFO",
		Message:  fmt.Sprintf("Scan completed: %d total findings", metadata.Summary.TotalFindings),
	}); err != nil {
		s.logger.Debug("Failed to save scan log", "error", err)
	}
}

// convertDBFindingToModel converts a database finding to a model finding.
func (s *Storage) convertDBFindingToModel(dbFinding *database.Finding) models.Finding {
	finding := models.Finding{
		ID:          fmt.Sprintf("%d", dbFinding.ID),
		Scanner:     dbFinding.Scanner,
		Severity:    string(dbFinding.Severity),
		Title:       dbFinding.Title,
		Description: dbFinding.Description,
		Resource:    dbFinding.Resource,
		Metadata:    make(map[string]string),
	}

	// Extract technical details
	if len(dbFinding.TechnicalDetails) > 0 {
		var details map[string]any
		if err := json.Unmarshal(dbFinding.TechnicalDetails, &details); err == nil {
			// Use original finding ID if available
			if originalID, ok := details["original_id"].(string); ok && originalID != "" {
				finding.ID = originalID
			}

			// Extract known fields
			if typ, ok := details["type"].(string); ok {
				finding.Type = typ
			}
			if rem, ok := details["remediation"].(string); ok {
				finding.Remediation = rem
			}

			// Extract business context
			if impact, ok := details["business_impact"].(string); ok {
				if finding.BusinessContext == nil {
					finding.BusinessContext = &models.BusinessContext{}
				}
				finding.BusinessContext.BusinessImpact = impact
			}
			if owner, ok := details["owner"].(string); ok {
				if finding.BusinessContext == nil {
					finding.BusinessContext = &models.BusinessContext{}
				}
				finding.BusinessContext.Owner = owner
			}

			// Add remaining fields to metadata
			for k, v := range details {
				if k != "type" && k != "remediation" && k != "business_impact" && k != "owner" && k != "original_id" {
					if strVal, ok := v.(string); ok {
						finding.Metadata[k] = strVal
					}
				}
			}
		}
	}

	return finding
}
