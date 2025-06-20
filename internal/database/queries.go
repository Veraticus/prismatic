package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// CreateScan creates a new scan record.
func (db *DB) CreateScan(ctx context.Context, scan *Scan) (int64, error) {
	// Convert regions to JSON
	regionsJSON, err := json.Marshal(scan.AWSRegions)
	if err != nil {
		return 0, fmt.Errorf("marshaling regions: %w", err)
	}

	query := `
		INSERT INTO scans (aws_profile, aws_regions, kube_context, scanners, status, started_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`

	result, err := db.ExecContext(ctx, query,
		scan.AWSProfile,
		string(regionsJSON),
		scan.KubeContext,
		scan.Scanners,
		scan.Status,
		scan.StartedAt,
	)
	if err != nil {
		return 0, fmt.Errorf("inserting scan: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("getting last insert id: %w", err)
	}

	return id, nil
}

// UpdateScanStatus updates the status of a scan.
func (db *DB) UpdateScanStatus(ctx context.Context, scanID int64, status ScanStatus, errorDetails *string) error {
	var query string
	var args []any

	if status == ScanStatusCompleted || status == ScanStatusFailed {
		query = `
			UPDATE scans 
			SET status = ?, completed_at = ?, error_details = ?
			WHERE id = ?
		`
		args = []any{status, time.Now(), errorDetails, scanID}
	} else {
		query = `
			UPDATE scans 
			SET status = ?, error_details = ?
			WHERE id = ?
		`
		args = []any{status, errorDetails, scanID}
	}

	result, err := db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("updating scan status: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("getting rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("scan %d not found", scanID)
	}

	return nil
}

// BatchInsertFindings inserts multiple findings efficiently.
func (db *DB) BatchInsertFindings(ctx context.Context, scanID int64, findings []*Finding) error {
	if len(findings) == 0 {
		return nil
	}

	// Process in chunks to avoid SQL query size limits
	const chunkSize = 500

	for i := 0; i < len(findings); i += chunkSize {
		end := i + chunkSize
		if end > len(findings) {
			end = len(findings)
		}

		chunk := findings[i:end]
		if err := db.insertFindingChunk(ctx, scanID, chunk); err != nil {
			return fmt.Errorf("inserting chunk %d-%d: %w", i, end, err)
		}
	}

	return nil
}

// insertFindingChunk inserts a chunk of findings in a single transaction.
func (db *DB) insertFindingChunk(ctx context.Context, scanID int64, findings []*Finding) error {
	return db.InTransaction(ctx, func(tx *sql.Tx) error {
		// Prepare statement for reuse
		stmt, err := tx.PrepareContext(ctx, `
			INSERT INTO findings (scan_id, scanner, severity, title, description, resource, technical_details)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`)
		if err != nil {
			return fmt.Errorf("preparing statement: %w", err)
		}
		defer func() {
			_ = stmt.Close()
		}()

		// Insert each finding
		for _, finding := range findings {
			_, err := stmt.ExecContext(ctx,
				scanID,
				finding.Scanner,
				finding.Severity,
				finding.Title,
				finding.Description,
				finding.Resource,
				finding.TechnicalDetails,
			)
			if err != nil {
				return fmt.Errorf("inserting finding: %w", err)
			}
		}

		return nil
	})
}

// GetScan retrieves a scan by ID.
func (db *DB) GetScan(ctx context.Context, scanID int64) (*Scan, error) {
	query := `
		SELECT id, aws_profile, aws_regions, kube_context, scanners, 
		       started_at, completed_at, status, error_details
		FROM scans
		WHERE id = ?
	`

	scan := &Scan{}
	var regionsJSON string

	err := db.QueryRowContext(ctx, query, scanID).Scan(
		&scan.ID,
		&scan.AWSProfile,
		&regionsJSON,
		&scan.KubeContext,
		&scan.Scanners,
		&scan.StartedAt,
		&scan.CompletedAt,
		&scan.Status,
		&scan.ErrorDetails,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("scan %d not found", scanID)
	}
	if err != nil {
		return nil, fmt.Errorf("querying scan: %w", err)
	}

	// Parse regions JSON
	if regionsJSON != "" {
		if err := json.Unmarshal([]byte(regionsJSON), &scan.AWSRegions); err != nil {
			return nil, fmt.Errorf("unmarshaling regions: %w", err)
		}
	}

	return scan, nil
}

// ListScans retrieves scans with optional filtering and pagination.
func (db *DB) ListScans(ctx context.Context, filter ScanFilter) ([]*Scan, error) {
	query := `
		SELECT id, aws_profile, aws_regions, kube_context, scanners, 
		       started_at, completed_at, status, error_details
		FROM scans
		WHERE 1=1
	`

	var args []any

	// Apply filters
	if filter.Status != nil {
		query += " AND status = ?"
		args = append(args, *filter.Status)
	}

	if filter.AWSProfile != nil {
		query += " AND aws_profile = ?"
		args = append(args, *filter.AWSProfile)
	}

	// Order by most recent first
	query += " ORDER BY started_at DESC"

	// Apply pagination
	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)

		if filter.Offset > 0 {
			query += " OFFSET ?"
			args = append(args, filter.Offset)
		}
	}

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying scans: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var scans []*Scan
	for rows.Next() {
		scan := &Scan{}
		var regionsJSON string

		err := rows.Scan(
			&scan.ID,
			&scan.AWSProfile,
			&regionsJSON,
			&scan.KubeContext,
			&scan.Scanners,
			&scan.StartedAt,
			&scan.CompletedAt,
			&scan.Status,
			&scan.ErrorDetails,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning row: %w", err)
		}

		// Parse regions JSON
		if regionsJSON != "" {
			if err := json.Unmarshal([]byte(regionsJSON), &scan.AWSRegions); err != nil {
				return nil, fmt.Errorf("unmarshaling regions: %w", err)
			}
		}

		scans = append(scans, scan)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating rows: %w", err)
	}

	return scans, nil
}

// GetFindings retrieves findings for a scan with optional filtering.
func (db *DB) GetFindings(ctx context.Context, scanID int64, filter FindingFilter) ([]*Finding, error) {
	query := `
		SELECT id, scan_id, scanner, severity, title, description, 
		       resource, technical_details, created_at
		FROM findings
		WHERE scan_id = ?
	`

	args := []any{scanID}

	// Apply filters
	if filter.Scanner != nil {
		query += " AND scanner = ?"
		args = append(args, *filter.Scanner)
	}

	if filter.Severity != nil {
		query += " AND severity = ?"
		args = append(args, *filter.Severity)
	}

	if filter.Resource != nil {
		query += " AND resource LIKE ?"
		args = append(args, "%"+*filter.Resource+"%")
	}

	// Order by severity (critical first) and creation time
	query += ` ORDER BY 
		CASE severity 
			WHEN 'CRITICAL' THEN 1 
			WHEN 'HIGH' THEN 2 
			WHEN 'MEDIUM' THEN 3 
			WHEN 'LOW' THEN 4 
			WHEN 'INFO' THEN 5 
		END, 
		created_at DESC`

	// Apply pagination
	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)

		if filter.Offset > 0 {
			query += " OFFSET ?"
			args = append(args, filter.Offset)
		}
	}

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying findings: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var findings []*Finding
	for rows.Next() {
		finding := &Finding{}
		var technicalDetails sql.NullString

		err := rows.Scan(
			&finding.ID,
			&finding.ScanID,
			&finding.Scanner,
			&finding.Severity,
			&finding.Title,
			&finding.Description,
			&finding.Resource,
			&technicalDetails,
			&finding.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning row: %w", err)
		}

		// Convert NullString to json.RawMessage
		if technicalDetails.Valid {
			finding.TechnicalDetails = json.RawMessage(technicalDetails.String)
		}

		findings = append(findings, finding)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating rows: %w", err)
	}

	return findings, nil
}

// GetFindingCounts returns counts of findings by severity for a scan.
func (db *DB) GetFindingCounts(ctx context.Context, scanID int64) (*FindingCounts, error) {
	query := `
		SELECT 
			COUNT(CASE WHEN severity = 'CRITICAL' THEN 1 END) as critical,
			COUNT(CASE WHEN severity = 'HIGH' THEN 1 END) as high,
			COUNT(CASE WHEN severity = 'MEDIUM' THEN 1 END) as medium,
			COUNT(CASE WHEN severity = 'LOW' THEN 1 END) as low,
			COUNT(CASE WHEN severity = 'INFO' THEN 1 END) as info,
			COUNT(*) as total
		FROM findings
		WHERE scan_id = ?
	`

	counts := &FindingCounts{}
	err := db.QueryRowContext(ctx, query, scanID).Scan(
		&counts.Critical,
		&counts.High,
		&counts.Medium,
		&counts.Low,
		&counts.Info,
		&counts.Total,
	)
	if err != nil {
		return nil, fmt.Errorf("querying finding counts: %w", err)
	}

	return counts, nil
}

// CreateSuppression creates a new suppression for a finding.
func (db *DB) CreateSuppression(ctx context.Context, suppression *Suppression) error {
	query := `
		INSERT INTO suppressions (finding_id, reason, suppressed_by)
		VALUES (?, ?, ?)
	`

	result, err := db.ExecContext(ctx, query,
		suppression.FindingID,
		suppression.Reason,
		suppression.SuppressedBy,
	)
	if err != nil {
		return fmt.Errorf("inserting suppression: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("getting last insert id: %w", err)
	}

	suppression.ID = id
	return nil
}

// GetSuppressions retrieves all suppressions for a finding.
func (db *DB) GetSuppressions(ctx context.Context, findingID int64) ([]*Suppression, error) {
	query := `
		SELECT id, finding_id, reason, suppressed_by, suppressed_at
		FROM suppressions
		WHERE finding_id = ?
		ORDER BY suppressed_at DESC
	`

	rows, err := db.QueryContext(ctx, query, findingID)
	if err != nil {
		return nil, fmt.Errorf("querying suppressions: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var suppressions []*Suppression
	for rows.Next() {
		suppression := &Suppression{}

		err := rows.Scan(
			&suppression.ID,
			&suppression.FindingID,
			&suppression.Reason,
			&suppression.SuppressedBy,
			&suppression.SuppressedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning row: %w", err)
		}

		suppressions = append(suppressions, suppression)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating rows: %w", err)
	}

	return suppressions, nil
}

// DeleteScan deletes a scan and all associated findings.
func (db *DB) DeleteScan(ctx context.Context, scanID int64) error {
	return db.InTransaction(ctx, func(tx *sql.Tx) error {
		// Delete suppressions for findings in this scan
		_, err := tx.ExecContext(ctx, `
			DELETE FROM suppressions 
			WHERE finding_id IN (SELECT id FROM findings WHERE scan_id = ?)
		`, scanID)
		if err != nil {
			return fmt.Errorf("deleting suppressions: %w", err)
		}

		// Delete findings
		_, err = tx.ExecContext(ctx, "DELETE FROM findings WHERE scan_id = ?", scanID)
		if err != nil {
			return fmt.Errorf("deleting findings: %w", err)
		}

		// Delete scan
		result, err := tx.ExecContext(ctx, "DELETE FROM scans WHERE id = ?", scanID)
		if err != nil {
			return fmt.Errorf("deleting scan: %w", err)
		}

		rows, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("getting rows affected: %w", err)
		}

		if rows == 0 {
			return fmt.Errorf("scan %d not found", scanID)
		}

		return nil
	})
}

// GetScannerStats returns statistics about findings per scanner for a scan.
func (db *DB) GetScannerStats(ctx context.Context, scanID int64) (map[string]*FindingCounts, error) {
	query := `
		SELECT 
			scanner,
			COUNT(CASE WHEN severity = 'CRITICAL' THEN 1 END) as critical,
			COUNT(CASE WHEN severity = 'HIGH' THEN 1 END) as high,
			COUNT(CASE WHEN severity = 'MEDIUM' THEN 1 END) as medium,
			COUNT(CASE WHEN severity = 'LOW' THEN 1 END) as low,
			COUNT(CASE WHEN severity = 'INFO' THEN 1 END) as info,
			COUNT(*) as total
		FROM findings
		WHERE scan_id = ?
		GROUP BY scanner
	`

	rows, err := db.QueryContext(ctx, query, scanID)
	if err != nil {
		return nil, fmt.Errorf("querying scanner stats: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	stats := make(map[string]*FindingCounts)
	for rows.Next() {
		var scanner string
		counts := &FindingCounts{}

		err := rows.Scan(
			&scanner,
			&counts.Critical,
			&counts.High,
			&counts.Medium,
			&counts.Low,
			&counts.Info,
			&counts.Total,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning row: %w", err)
		}

		stats[scanner] = counts
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating rows: %w", err)
	}

	return stats, nil
}

// SearchFindings performs a text search across finding titles and descriptions.
func (db *DB) SearchFindings(ctx context.Context, scanID int64, searchTerm string, limit int) ([]*Finding, error) {
	query := `
		SELECT id, scan_id, scanner, severity, title, description, 
		       resource, technical_details, created_at
		FROM findings
		WHERE scan_id = ? 
		  AND (title LIKE ? OR description LIKE ? OR resource LIKE ?)
		ORDER BY 
			CASE severity 
				WHEN 'CRITICAL' THEN 1 
				WHEN 'HIGH' THEN 2 
				WHEN 'MEDIUM' THEN 3 
				WHEN 'LOW' THEN 4 
				WHEN 'INFO' THEN 5 
			END
		LIMIT ?
	`

	searchPattern := "%" + strings.ToLower(searchTerm) + "%"

	rows, err := db.QueryContext(ctx, query, scanID, searchPattern, searchPattern, searchPattern, limit)
	if err != nil {
		return nil, fmt.Errorf("searching findings: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var findings []*Finding
	for rows.Next() {
		finding := &Finding{}
		var technicalDetails sql.NullString

		err := rows.Scan(
			&finding.ID,
			&finding.ScanID,
			&finding.Scanner,
			&finding.Severity,
			&finding.Title,
			&finding.Description,
			&finding.Resource,
			&technicalDetails,
			&finding.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning row: %w", err)
		}

		// Convert NullString to json.RawMessage
		if technicalDetails.Valid {
			finding.TechnicalDetails = json.RawMessage(technicalDetails.String)
		}

		findings = append(findings, finding)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating rows: %w", err)
	}

	return findings, nil
}
