// Package storage handles persistence of scan results and findings.
package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/joshsymonds/prismatic/internal/enrichment"
	"github.com/joshsymonds/prismatic/internal/models"
	"github.com/joshsymonds/prismatic/pkg/logger"
	"github.com/joshsymonds/prismatic/pkg/pathutil"
)

// Storage handles saving and loading scan results.
type Storage struct {
	logger  logger.Logger
	baseDir string
}

// NewStorage creates a new storage instance.
func NewStorage(baseDir string) *Storage {
	return NewStorageWithLogger(baseDir, logger.GetGlobalLogger())
}

// NewStorageWithLogger creates a new storage instance with a custom logger.
func NewStorageWithLogger(baseDir string, log logger.Logger) *Storage {
	return &Storage{
		baseDir: baseDir,
		logger:  log,
	}
}

// SaveScanResults saves scan results to the output directory.
func (s *Storage) SaveScanResults(outputDir string, metadata *models.ScanMetadata) error {
	// Validate output directory path is safe (no directory traversal)
	validOutputDir, err := pathutil.ValidateDataPath(outputDir, "")
	if err != nil {
		return fmt.Errorf("invalid output directory: %w", err)
	}

	// Create output directory structure
	if mkErr := os.MkdirAll(validOutputDir, 0750); mkErr != nil {
		return fmt.Errorf("creating output directory: %w", mkErr)
	}

	rawDir := filepath.Join(validOutputDir, "raw")
	if mkErr := os.MkdirAll(rawDir, 0750); mkErr != nil {
		return fmt.Errorf("creating raw directory: %w", mkErr)
	}

	// Save metadata
	metadataPath, err := pathutil.JoinAndValidate(validOutputDir, "metadata.json")
	if err != nil {
		return fmt.Errorf("invalid metadata path: %w", err)
	}
	if saveErr := s.saveJSON(metadataPath, metadata); saveErr != nil {
		return fmt.Errorf("saving metadata: %w", saveErr)
	}
	s.logger.Debug("Saved metadata", "path", metadataPath)

	// Save raw scanner outputs
	for scanner, result := range metadata.Results {
		if len(result.RawOutput) > 0 {
			rawPath, rawErr := pathutil.JoinAndValidate(rawDir, fmt.Sprintf("%s.json", scanner))
			if rawErr != nil {
				s.logger.Warn("Invalid raw output path", "scanner", scanner, "error", rawErr)
				continue
			}
			if writeErr := os.WriteFile(rawPath, result.RawOutput, 0600); writeErr != nil {
				s.logger.Warn("Failed to save raw output", "scanner", scanner, "error", writeErr)
			} else {
				s.logger.Debug("Saved raw output", "scanner", scanner, "path", rawPath)
			}
		}
	}

	// Save consolidated findings
	allFindings := s.consolidateFindings(metadata)
	findingsPath, err := pathutil.JoinAndValidate(validOutputDir, "findings.json")
	if err != nil {
		return fmt.Errorf("invalid findings path: %w", err)
	}
	if saveErr := s.saveJSON(findingsPath, allFindings); saveErr != nil {
		return fmt.Errorf("saving findings: %w", saveErr)
	}
	s.logger.Debug("Saved findings", "path", findingsPath, "count", len(allFindings))

	// Note: EnrichedFindings are no longer saved separately.
	// Business context is now part of the Finding struct itself.

	// Save scan log
	logPath, err := pathutil.JoinAndValidate(validOutputDir, "scan.log")
	if err != nil {
		s.logger.Warn("Invalid scan log path", "error", err)
		return nil
	}
	if err := s.saveScanLog(logPath, metadata); err != nil {
		s.logger.Warn("Failed to save scan log", "error", err)
	}

	return nil
}

// LoadScanResults loads scan results from a directory.
func (s *Storage) LoadScanResults(scanDir string) (*models.ScanMetadata, error) {
	// Validate scan directory path is safe (no directory traversal)
	validScanDir, err := pathutil.ValidateDataPath(scanDir, "")
	if err != nil {
		return nil, fmt.Errorf("invalid scan directory: %w", err)
	}

	// Load metadata
	metadataPath, err := pathutil.JoinAndValidate(validScanDir, "metadata.json")
	if err != nil {
		return nil, fmt.Errorf("invalid metadata path: %w", err)
	}
	var metadata models.ScanMetadata
	if loadErr := s.loadJSON(metadataPath, &metadata); loadErr != nil {
		return nil, fmt.Errorf("loading metadata: %w", loadErr)
	}

	// Load findings
	findingsPath, err := pathutil.JoinAndValidate(validScanDir, "findings.json")
	if err != nil {
		s.logger.Warn("Invalid findings path", "error", err)
		// Not fatal - metadata might still be useful
	}
	var findings []models.Finding
	if err := s.loadJSON(findingsPath, &findings); err != nil {
		s.logger.Warn("Failed to load findings", "error", err)
		// Not fatal - metadata might still be useful
	}

	// Note: EnrichedFindings are no longer loaded separately.
	// Business context is now part of the Finding struct itself.

	// Reconstruct results if needed
	if metadata.Results == nil {
		metadata.Results = make(map[string]*models.ScanResult)
	}

	return &metadata, nil
}

// FindLatestScan finds the most recent scan directory.
func (s *Storage) FindLatestScan() (string, error) {
	scansDir := filepath.Join(s.baseDir, "scans")

	entries, err := os.ReadDir(scansDir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("no scans found")
		}
		return "", fmt.Errorf("reading scans directory: %w", err)
	}

	var latest string
	for _, entry := range entries {
		if entry.IsDir() {
			if latest == "" || entry.Name() > latest {
				latest = entry.Name()
			}
		}
	}

	if latest == "" {
		return "", fmt.Errorf("no scan directories found")
	}

	return filepath.Join(scansDir, latest), nil
}

// ListScans returns a list of available scans.
func (s *Storage) ListScans(client string, limit int) ([]ScanInfo, error) {
	scansDir := filepath.Join(s.baseDir, "scans")

	entries, err := os.ReadDir(scansDir)
	if err != nil {
		return nil, fmt.Errorf("reading scans directory: %w", err)
	}

	var scans []ScanInfo

	// Read scans in reverse order (newest first)
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		if !entry.IsDir() {
			continue
		}

		// Load metadata
		metadataPath, err := pathutil.JoinAndValidate(scansDir, entry.Name(), "metadata.json")
		if err != nil {
			s.logger.Debug("Invalid metadata path", "dir", entry.Name(), "error", err)
			continue
		}
		var metadata models.ScanMetadata
		if err := s.loadJSON(metadataPath, &metadata); err != nil {
			s.logger.Debug("Skipping invalid scan directory", "dir", entry.Name(), "error", err)
			continue
		}

		// Filter by client if specified
		if client != "" && metadata.ClientName != client {
			continue
		}

		info := ScanInfo{
			ID:          entry.Name(),
			Path:        filepath.Join(scansDir, entry.Name()),
			ClientName:  metadata.ClientName,
			Environment: metadata.Environment,
			StartTime:   metadata.StartTime,
			EndTime:     metadata.EndTime,
			Summary:     metadata.Summary,
		}

		scans = append(scans, info)

		if limit > 0 && len(scans) >= limit {
			break
		}
	}

	return scans, nil
}

// ScanInfo provides summary information about a scan.
type ScanInfo struct {
	ID          string
	Path        string
	ClientName  string
	Environment string
	StartTime   time.Time
	EndTime     time.Time
	Summary     models.ScanSummary
}

// consolidateFindings extracts all findings from scan results.
func (s *Storage) consolidateFindings(metadata *models.ScanMetadata) []models.Finding {
	// Count total findings first to warn about memory usage
	totalCount := 0
	for _, result := range metadata.Results {
		totalCount += len(result.Findings)
	}

	// Warn if too many findings
	if totalCount > 10000 {
		s.logger.Warn("Large number of findings may cause memory issues",
			"count", totalCount)
	}

	var allFindings []models.Finding
	for _, result := range metadata.Results {
		allFindings = append(allFindings, result.Findings...)
	}

	return allFindings
}

// saveJSON saves data as JSON to a file.
func (s *Storage) saveJSON(path string, data any) (err error) {
	// Path should already be validated by caller
	file, err := os.Create(path) // #nosec G304 - path is validated by caller
	if err != nil {
		return err
	}
	defer func() {
		if cerr := file.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

// loadJSON loads JSON data from a file.
func (s *Storage) loadJSON(path string, data any) (err error) {
	// Path should already be validated by caller
	file, err := os.Open(path) // #nosec G304 - path is validated by caller
	if err != nil {
		return err
	}
	defer func() {
		if cerr := file.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	return json.NewDecoder(file).Decode(data)
}

// saveScanLog saves a human-readable scan log.
func (s *Storage) saveScanLog(path string, metadata *models.ScanMetadata) (err error) {
	// Path should already be validated by caller
	file, err := os.Create(path) // #nosec G304 - path is validated by caller
	if err != nil {
		return err
	}
	defer func() {
		if cerr := file.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	// Use a helper to check fprintf errors
	w := func(format string, args ...any) error {
		_, err := fmt.Fprintf(file, format, args...)
		return err
	}

	if err := w("Prismatic Security Scan Log\n"); err != nil {
		return fmt.Errorf("writing header: %w", err)
	}
	if err := w("===========================\n\n"); err != nil {
		return fmt.Errorf("writing separator: %w", err)
	}
	if err := w("Client: %s\n", metadata.ClientName); err != nil {
		return fmt.Errorf("writing client: %w", err)
	}
	if err := w("Environment: %s\n", metadata.Environment); err != nil {
		return fmt.Errorf("writing environment: %w", err)
	}
	if err := w("Start Time: %s\n", metadata.StartTime.Format("2006-01-02 15:04:05")); err != nil {
		return fmt.Errorf("writing start time: %w", err)
	}
	if err := w("End Time: %s\n", metadata.EndTime.Format("2006-01-02 15:04:05")); err != nil {
		return fmt.Errorf("writing end time: %w", err)
	}
	if err := w("Duration: %s\n\n", metadata.EndTime.Sub(metadata.StartTime)); err != nil {
		return fmt.Errorf("writing duration: %w", err)
	}

	if err := w("Scanners Run:\n"); err != nil {
		return fmt.Errorf("writing scanners header: %w", err)
	}
	for _, scanner := range metadata.Scanners {
		status := "✓"
		if result, ok := metadata.Results[scanner]; ok && result.Error != "" {
			status = "✗"
		}
		if err := w("  %s %s\n", status, scanner); err != nil {
			return fmt.Errorf("writing scanner status: %w", err)
		}
	}

	if err := w("\nSummary:\n"); err != nil {
		return fmt.Errorf("writing summary header: %w", err)
	}
	if err := w("  Total Findings: %d\n", metadata.Summary.TotalFindings); err != nil {
		return fmt.Errorf("writing total findings: %w", err)
	}
	if err := w("  Suppressed: %d\n", metadata.Summary.SuppressedCount); err != nil {
		return fmt.Errorf("writing suppressed count: %w", err)
	}
	if err := w("\nBy Severity:\n"); err != nil {
		return fmt.Errorf("writing severity header: %w", err)
	}
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if count, ok := metadata.Summary.BySeverity[sev]; ok && count > 0 {
			if err := w("  %s: %d\n", sev, count); err != nil {
				return fmt.Errorf("writing severity count: %w", err)
			}
		}
	}

	if len(metadata.Summary.FailedScanners) > 0 {
		if err := w("\nFailed Scanners:\n"); err != nil {
			return fmt.Errorf("writing failed scanners header: %w", err)
		}
		for _, scanner := range metadata.Summary.FailedScanners {
			if err := w("  - %s\n", scanner); err != nil {
				return fmt.Errorf("writing failed scanner: %w", err)
			}
			if result, ok := metadata.Results[scanner]; ok && result.Error != "" {
				if err := w("    Error: %s\n", result.Error); err != nil {
					return fmt.Errorf("writing scanner error: %w", err)
				}
			}
		}
	}

	return nil
}

// GetScanDirectory returns the base directory for the storage.
func (s *Storage) GetScanDirectory() string {
	return s.baseDir
}

// LoadResults loads results for a specific scanner from the current scan.
func (s *Storage) LoadResults(scanner string) (*models.ScanResult, error) {
	// Load metadata first
	metadataPath := filepath.Join(s.baseDir, "metadata.json")
	var metadata models.ScanMetadata
	if err := s.loadJSON(metadataPath, &metadata); err != nil {
		return nil, fmt.Errorf("loading metadata: %w", err)
	}

	// Check if scanner results exist
	result, ok := metadata.Results[scanner]
	if !ok {
		return nil, fmt.Errorf("no results found for scanner: %s", scanner)
	}

	return result, nil
}

// LoadEnrichments loads AI enrichments from the scan directory.
func (s *Storage) LoadEnrichments(scanDir string) ([]enrichment.FindingEnrichment, *enrichment.EnrichmentMetadata, error) {
	// Validate scan directory path is safe (no directory traversal)
	validScanDir, err := pathutil.ValidateDataPath(scanDir, "")
	if err != nil {
		return nil, nil, fmt.Errorf("invalid scan directory: %w", err)
	}

	enrichmentDir := filepath.Join(validScanDir, "enrichments")

	// Check if enrichments directory exists
	if _, err := os.Stat(enrichmentDir); os.IsNotExist(err) {
		// No enrichments found is not an error - return empty
		return []enrichment.FindingEnrichment{}, nil, nil
	}

	// Load metadata
	metadataPath, err := pathutil.JoinAndValidate(enrichmentDir, "metadata.json")
	if err != nil {
		return nil, nil, fmt.Errorf("invalid metadata path: %w", err)
	}

	var metadata enrichment.EnrichmentMetadata
	if err := s.loadJSON(metadataPath, &metadata); err != nil {
		// If metadata doesn't exist, enrichments may be incomplete
		s.logger.Warn("Failed to load enrichment metadata", "error", err)
	}

	// Load individual enrichment files
	entries, err := os.ReadDir(enrichmentDir)
	if err != nil {
		return nil, nil, fmt.Errorf("reading enrichments directory: %w", err)
	}

	var enrichments []enrichment.FindingEnrichment
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || entry.Name() == "metadata.json" {
			continue
		}

		enrichmentPath, err := pathutil.JoinAndValidate(enrichmentDir, entry.Name())
		if err != nil {
			s.logger.Debug("Invalid enrichment path", "file", entry.Name(), "error", err)
			continue
		}

		var enrichment enrichment.FindingEnrichment
		if err := s.loadJSON(enrichmentPath, &enrichment); err != nil {
			s.logger.Warn("Failed to load enrichment", "file", entry.Name(), "error", err)
			continue
		}

		enrichments = append(enrichments, enrichment)
	}

	s.logger.Debug("Loaded enrichments", "count", len(enrichments))
	return enrichments, &metadata, nil
}

// SaveEnrichments saves AI enrichments to the scan directory.
func (s *Storage) SaveEnrichments(scanDir string, enrichments []enrichment.FindingEnrichment, metadata *enrichment.EnrichmentMetadata) error {
	// Validate scan directory path is safe (no directory traversal)
	validScanDir, err := pathutil.ValidateDataPath(scanDir, "")
	if err != nil {
		return fmt.Errorf("invalid scan directory: %w", err)
	}

	enrichmentDir := filepath.Join(validScanDir, "enrichments")

	// Create enrichments directory
	if err := os.MkdirAll(enrichmentDir, 0750); err != nil {
		return fmt.Errorf("creating enrichments directory: %w", err)
	}

	// Save individual enrichments
	for _, enrichment := range enrichments {
		filename := fmt.Sprintf("%s.json", enrichment.FindingID)
		enrichmentPath, err := pathutil.JoinAndValidate(enrichmentDir, filename)
		if err != nil {
			s.logger.Warn("Invalid enrichment path", "finding_id", enrichment.FindingID, "error", err)
			continue
		}

		if err := s.saveJSON(enrichmentPath, enrichment); err != nil {
			s.logger.Warn("Failed to save enrichment", "finding_id", enrichment.FindingID, "error", err)
			continue
		}
	}

	// Save metadata if provided
	if metadata != nil {
		metadataPath, err := pathutil.JoinAndValidate(enrichmentDir, "metadata.json")
		if err != nil {
			return fmt.Errorf("invalid metadata path: %w", err)
		}

		if err := s.saveJSON(metadataPath, metadata); err != nil {
			return fmt.Errorf("saving enrichment metadata: %w", err)
		}

		s.logger.Debug("Saved enrichment metadata", "path", metadataPath)
	}

	s.logger.Debug("Saved enrichments", "count", len(enrichments))
	return nil
}
