package database

import (
	"context"
	"database/sql"
	"testing"
)

func TestMigrations(t *testing.T) {
	db, err := NewMemoryDB()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("Failed to close database: %v", closeErr)
		}
	}()

	ctx := context.Background()

	// Test that migrations have already run (from New())
	version, err := db.GetMigrationVersion(ctx)
	if err != nil {
		t.Fatalf("Failed to get migration version: %v", err)
	}
	if version < 1 {
		t.Errorf("Expected migration version >= 1, got %d", version)
	}

	// Verify all expected tables exist
	tables := []struct {
		name    string
		columns []string
	}{
		{
			name:    "scans",
			columns: []string{"id", "aws_profile", "aws_regions", "kube_context", "scanners", "started_at", "completed_at", "status", "error_details"},
		},
		{
			name:    "findings",
			columns: []string{"id", "scan_id", "scanner", "severity", "title", "description", "resource", "technical_details", "created_at"},
		},
		{
			name:    "suppressions",
			columns: []string{"id", "finding_id", "reason", "suppressed_by", "suppressed_at"},
		},
		{
			name:    "migrations",
			columns: []string{"version", "name", "applied_at"},
		},
	}

	for _, table := range tables {
		// Check table exists
		var count int
		err := db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table.name).Scan(&count)
		if err != nil {
			t.Fatalf("Failed to check table %s: %v", table.name, err)
		}
		if count != 1 {
			t.Errorf("Expected table %s to exist", table.name)
			continue
		}

		// Check columns exist using a function to properly handle defer
		func() {
			rows, err := db.QueryContext(ctx, "PRAGMA table_info("+table.name+")")
			if err != nil {
				t.Fatalf("Failed to get table info for %s: %v", table.name, err)
			}
			defer func() {
				if err := rows.Close(); err != nil {
					t.Errorf("Failed to close rows: %v", err)
				}
			}()

			columnMap := make(map[string]bool)
			for rows.Next() {
				var cid int
				var name, ctype string
				var notnull, pk int
				var dflt sql.NullString

				if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
					t.Fatalf("Failed to scan column info: %v", err)
				}
				columnMap[name] = true
			}

			if err := rows.Err(); err != nil {
				t.Fatalf("Failed to iterate rows: %v", err)
			}

			for _, col := range table.columns {
				if !columnMap[col] {
					t.Errorf("Expected column %s.%s to exist", table.name, col)
				}
			}
		}()
	}

	// Verify indexes exist
	indexes := []struct {
		name  string
		table string
	}{
		{"idx_findings_scan", "findings"},
		{"idx_findings_severity", "findings"},
		{"idx_suppressions_finding", "suppressions"},
	}

	for _, idx := range indexes {
		var count int
		err := db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?", idx.name).Scan(&count)
		if err != nil {
			t.Fatalf("Failed to check index %s: %v", idx.name, err)
		}
		if count != 1 {
			t.Errorf("Expected index %s to exist", idx.name)
		}
	}
}

func TestMigrationIdempotency(t *testing.T) {
	db, err := NewMemoryDB()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("Failed to close database: %v", closeErr)
		}
	}()

	ctx := context.Background()

	// Get initial version
	version1, err := db.GetMigrationVersion(ctx)
	if err != nil {
		t.Fatalf("Failed to get initial version: %v", err)
	}

	// Run migrations again
	err = db.Migrate(ctx)
	if err != nil {
		t.Fatalf("Failed to run migrations again: %v", err)
	}

	// Version should be the same
	version2, err := db.GetMigrationVersion(ctx)
	if err != nil {
		t.Fatalf("Failed to get version after re-migration: %v", err)
	}

	if version1 != version2 {
		t.Errorf("Migration version changed after re-running: %d -> %d", version1, version2)
	}
}

func TestConstraints(t *testing.T) {
	db, err := NewMemoryDB()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("Failed to close database: %v", closeErr)
		}
	}()

	ctx := context.Background()

	// Test scan status constraint
	_, err = db.ExecContext(ctx,
		"INSERT INTO scans (status) VALUES (?)", "invalid_status")
	if err == nil {
		t.Error("Expected error for invalid scan status")
	}

	// Test finding severity constraint
	_, err = db.ExecContext(ctx,
		"INSERT INTO findings (scan_id, scanner, severity, title) VALUES (?, ?, ?, ?)",
		1, "test", "INVALID", "test")
	if err == nil {
		t.Error("Expected error for invalid finding severity")
	}

	// Test foreign key constraint (after enabling in pragmas)
	// First create a valid scan
	result, err := db.ExecContext(ctx,
		"INSERT INTO scans (status) VALUES (?)", "running")
	if err != nil {
		t.Fatalf("Failed to create scan: %v", err)
	}

	scanID, _ := result.LastInsertId()

	// This should work
	_, err = db.ExecContext(ctx,
		"INSERT INTO findings (scan_id, scanner, severity, title) VALUES (?, ?, ?, ?)",
		scanID, "test", "HIGH", "test finding")
	if err != nil {
		t.Errorf("Failed to insert finding with valid scan_id: %v", err)
	}

	// This should fail due to foreign key
	_, err = db.ExecContext(ctx,
		"INSERT INTO findings (scan_id, scanner, severity, title) VALUES (?, ?, ?, ?)",
		99999, "test", "HIGH", "test finding")
	if err == nil {
		t.Error("Expected error for invalid scan_id foreign key")
	}
}
