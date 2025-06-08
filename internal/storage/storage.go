// Package storage handles persistence of scan results and findings.
package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Veraticus/prismatic/internal/models"
	"github.com/Veraticus/prismatic/pkg/logger"
)

// Storage handles saving and loading scan results.
type Storage struct {
	baseDir string
}

// NewStorage creates a new storage instance.
func NewStorage(baseDir string) *Storage {
	return &Storage{
		baseDir: baseDir,
	}
}

// SaveScanResults saves scan results to the output directory.
func (s *Storage) SaveScanResults(outputDir string, metadata *models.ScanMetadata) error {
	// Create output directory structure
	if err := os.MkdirAll(outputDir, 0750); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	rawDir := filepath.Join(outputDir, "raw")
	if err := os.MkdirAll(rawDir, 0750); err != nil {
		return fmt.Errorf("creating raw directory: %w", err)
	}

	// Save metadata
	metadataPath := filepath.Join(outputDir, "metadata.json")
	if err := s.saveJSON(metadataPath, metadata); err != nil {
		return fmt.Errorf("saving metadata: %w", err)
	}
	logger.Debug("Saved metadata", "path", metadataPath)

	// Save raw scanner outputs
	for scanner, result := range metadata.Results {
		if len(result.RawOutput) > 0 {
			rawPath := filepath.Join(rawDir, fmt.Sprintf("%s.json", scanner))
			if err := os.WriteFile(rawPath, result.RawOutput, 0600); err != nil {
				logger.Warn("Failed to save raw output", "scanner", scanner, "error", err)
			} else {
				logger.Debug("Saved raw output", "scanner", scanner, "path", rawPath)
			}
		}
	}

	// Save consolidated findings
	allFindings := s.consolidateFindings(metadata)
	findingsPath := filepath.Join(outputDir, "findings.json")
	if err := s.saveJSON(findingsPath, allFindings); err != nil {
		return fmt.Errorf("saving findings: %w", err)
	}
	logger.Debug("Saved findings", "path", findingsPath, "count", len(allFindings))

	// Save scan log
	logPath := filepath.Join(outputDir, "scan.log")
	if err := s.saveScanLog(logPath, metadata); err != nil {
		logger.Warn("Failed to save scan log", "error", err)
	}

	return nil
}

// LoadScanResults loads scan results from a directory.
func (s *Storage) LoadScanResults(scanDir string) (*models.ScanMetadata, error) {
	// Load metadata
	metadataPath := filepath.Join(scanDir, "metadata.json")
	var metadata models.ScanMetadata
	if err := s.loadJSON(metadataPath, &metadata); err != nil {
		return nil, fmt.Errorf("loading metadata: %w", err)
	}

	// Load findings
	findingsPath := filepath.Join(scanDir, "findings.json")
	var findings []models.Finding
	if err := s.loadJSON(findingsPath, &findings); err != nil {
		logger.Warn("Failed to load findings", "error", err)
		// Not fatal - metadata might still be useful
	}

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
		metadataPath := filepath.Join(scansDir, entry.Name(), "metadata.json")
		var metadata models.ScanMetadata
		if err := s.loadJSON(metadataPath, &metadata); err != nil {
			logger.Debug("Skipping invalid scan directory", "dir", entry.Name(), "error", err)
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
	var allFindings []models.Finding

	for _, result := range metadata.Results {
		allFindings = append(allFindings, result.Findings...)
	}

	return allFindings
}

// saveJSON saves data as JSON to a file.
func (s *Storage) saveJSON(path string, data any) (err error) {
	file, err := os.Create(path) //nolint:gosec // Path is internally generated and validated //nolint:gosec // Path is internally generated and validated
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
	file, err := os.Open(path) //nolint:gosec // Path is internally generated and validated
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
	file, err := os.Create(path) //nolint:gosec // Path is internally generated and validated
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
