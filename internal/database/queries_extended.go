package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrNoMetadata is returned when no metadata is found for a scan.
var ErrNoMetadata = errors.New("no metadata found")

// SaveScannerOutput saves raw scanner output to the database.
func (db *DB) SaveScannerOutput(ctx context.Context, scanID int64, scanner string, rawOutput string) error {
	query := `
		INSERT INTO scanner_outputs (scan_id, scanner, raw_output)
		VALUES (?, ?, ?)
	`

	_, err := db.ExecContext(ctx, query, scanID, scanner, rawOutput)
	if err != nil {
		return fmt.Errorf("saving scanner output: %w", err)
	}

	return nil
}

// GetScannerOutputs retrieves all scanner outputs for a scan.
func (db *DB) GetScannerOutputs(ctx context.Context, scanID int64) ([]*ScannerOutput, error) {
	query := `
		SELECT id, scan_id, scanner, raw_output, created_at
		FROM scanner_outputs
		WHERE scan_id = ?
		ORDER BY created_at
	`

	rows, err := db.QueryContext(ctx, query, scanID)
	if err != nil {
		return nil, fmt.Errorf("querying scanner outputs: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var outputs []*ScannerOutput
	for rows.Next() {
		output := &ScannerOutput{}
		err := rows.Scan(
			&output.ID,
			&output.ScanID,
			&output.Scanner,
			&output.RawOutput,
			&output.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning row: %w", err)
		}
		outputs = append(outputs, output)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating rows: %w", err)
	}

	return outputs, nil
}

// SaveFindingEnrichment saves AI enrichment for a finding.
func (db *DB) SaveFindingEnrichment(ctx context.Context, enrichment *FindingEnrichment) error {
	query := `
		INSERT INTO finding_enrichments (finding_id, scan_id, business_impact, 
			remediation_steps, risk_score, estimated_effort, ai_analysis)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	result, err := db.ExecContext(ctx, query,
		enrichment.FindingID,
		enrichment.ScanID,
		enrichment.BusinessImpact,
		enrichment.RemediationSteps,
		enrichment.RiskScore,
		enrichment.EstimatedEffort,
		enrichment.AIAnalysis,
	)
	if err != nil {
		return fmt.Errorf("saving finding enrichment: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("getting last insert id: %w", err)
	}

	enrichment.ID = id
	return nil
}

// GetFindingEnrichments retrieves enrichments for findings in a scan.
func (db *DB) GetFindingEnrichments(ctx context.Context, scanID int64) ([]*FindingEnrichment, error) {
	query := `
		SELECT id, finding_id, scan_id, business_impact, remediation_steps,
			risk_score, estimated_effort, ai_analysis, created_at
		FROM finding_enrichments
		WHERE scan_id = ?
		ORDER BY created_at
	`

	rows, err := db.QueryContext(ctx, query, scanID)
	if err != nil {
		return nil, fmt.Errorf("querying finding enrichments: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var enrichments []*FindingEnrichment
	for rows.Next() {
		enrichment := &FindingEnrichment{}
		var aiAnalysis sql.NullString

		err := rows.Scan(
			&enrichment.ID,
			&enrichment.FindingID,
			&enrichment.ScanID,
			&enrichment.BusinessImpact,
			&enrichment.RemediationSteps,
			&enrichment.RiskScore,
			&enrichment.EstimatedEffort,
			&aiAnalysis,
			&enrichment.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning row: %w", err)
		}

		if aiAnalysis.Valid {
			enrichment.AIAnalysis = json.RawMessage(aiAnalysis.String)
		}

		enrichments = append(enrichments, enrichment)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating rows: %w", err)
	}

	return enrichments, nil
}

// SaveScanMetadata saves additional metadata for a scan.
func (db *DB) SaveScanMetadata(ctx context.Context, metadata *ScanMetadata) error {
	query := `
		INSERT INTO scan_metadata (scan_id, client_name, environment, 
			configuration, summary, scanner_versions)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(scan_id) DO UPDATE SET
			client_name = excluded.client_name,
			environment = excluded.environment,
			configuration = excluded.configuration,
			summary = excluded.summary,
			scanner_versions = excluded.scanner_versions
	`

	result, err := db.ExecContext(ctx, query,
		metadata.ScanID,
		metadata.ClientName,
		metadata.Environment,
		metadata.Configuration,
		metadata.Summary,
		metadata.ScannerVersions,
	)
	if err != nil {
		return fmt.Errorf("saving scan metadata: %w", err)
	}

	if metadata.ID == 0 {
		id, err := result.LastInsertId()
		if err != nil {
			return fmt.Errorf("getting last insert id: %w", err)
		}
		metadata.ID = id
	}

	return nil
}

// GetScanMetadata retrieves metadata for a scan.
func (db *DB) GetScanMetadata(ctx context.Context, scanID int64) (*ScanMetadata, error) {
	query := `
		SELECT id, scan_id, client_name, environment, configuration,
			summary, scanner_versions, created_at
		FROM scan_metadata
		WHERE scan_id = ?
	`

	metadata := &ScanMetadata{}
	var config, summary, versions sql.NullString

	err := db.QueryRowContext(ctx, query, scanID).Scan(
		&metadata.ID,
		&metadata.ScanID,
		&metadata.ClientName,
		&metadata.Environment,
		&config,
		&summary,
		&versions,
		&metadata.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNoMetadata
	}
	if err != nil {
		return nil, fmt.Errorf("querying scan metadata: %w", err)
	}

	// Convert NullString to json.RawMessage
	if config.Valid {
		metadata.Configuration = json.RawMessage(config.String)
	}
	if summary.Valid {
		metadata.Summary = json.RawMessage(summary.String)
	}
	if versions.Valid {
		metadata.ScannerVersions = json.RawMessage(versions.String)
	}

	return metadata, nil
}

// SaveScanLog saves a log entry for a scan.
func (db *DB) SaveScanLog(ctx context.Context, log *ScanLog) error {
	query := `
		INSERT INTO scan_logs (scan_id, log_level, message, scanner)
		VALUES (?, ?, ?, ?)
	`

	result, err := db.ExecContext(ctx, query,
		log.ScanID,
		log.LogLevel,
		log.Message,
		log.Scanner,
	)
	if err != nil {
		return fmt.Errorf("saving scan log: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("getting last insert id: %w", err)
	}

	log.ID = id
	return nil
}

// GetScanLogs retrieves logs for a scan.
func (db *DB) GetScanLogs(ctx context.Context, scanID int64) ([]*ScanLog, error) {
	query := `
		SELECT id, scan_id, log_level, message, scanner, created_at
		FROM scan_logs
		WHERE scan_id = ?
		ORDER BY created_at
	`

	rows, err := db.QueryContext(ctx, query, scanID)
	if err != nil {
		return nil, fmt.Errorf("querying scan logs: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var logs []*ScanLog
	for rows.Next() {
		log := &ScanLog{}
		err := rows.Scan(
			&log.ID,
			&log.ScanID,
			&log.LogLevel,
			&log.Message,
			&log.Scanner,
			&log.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning row: %w", err)
		}
		logs = append(logs, log)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating rows: %w", err)
	}

	return logs, nil
}

// UpdateScanProgress updates or inserts scanner progress.
func (db *DB) UpdateScanProgress(ctx context.Context, progress *ScanProgress) error {
	query := `
		INSERT INTO scan_progress (scan_id, scanner, status, progress_percent, 
			current_step, error_message, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(scan_id, scanner) DO UPDATE SET
			status = excluded.status,
			progress_percent = excluded.progress_percent,
			current_step = excluded.current_step,
			error_message = excluded.error_message,
			updated_at = excluded.updated_at
	`

	_, err := db.ExecContext(ctx, query,
		progress.ScanID,
		progress.Scanner,
		progress.Status,
		progress.ProgressPercent,
		progress.CurrentStep,
		progress.ErrorMessage,
		time.Now(),
	)
	if err != nil {
		return fmt.Errorf("updating scan progress: %w", err)
	}

	return nil
}

// GetScanProgress retrieves progress for all scanners in a scan.
func (db *DB) GetScanProgress(ctx context.Context, scanID int64) ([]*ScanProgress, error) {
	query := `
		SELECT id, scan_id, scanner, status, progress_percent, 
			current_step, error_message, updated_at
		FROM scan_progress
		WHERE scan_id = ?
		ORDER BY scanner
	`

	rows, err := db.QueryContext(ctx, query, scanID)
	if err != nil {
		return nil, fmt.Errorf("querying scan progress: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var progressList []*ScanProgress
	for rows.Next() {
		progress := &ScanProgress{}
		err := rows.Scan(
			&progress.ID,
			&progress.ScanID,
			&progress.Scanner,
			&progress.Status,
			&progress.ProgressPercent,
			&progress.CurrentStep,
			&progress.ErrorMessage,
			&progress.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning row: %w", err)
		}
		progressList = append(progressList, progress)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating rows: %w", err)
	}

	return progressList, nil
}
