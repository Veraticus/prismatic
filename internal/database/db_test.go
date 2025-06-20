package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		opts    []Option
		wantErr bool
	}{
		{
			name: "in-memory database",
			path: ":memory:",
		},
		{
			name: "with options",
			path: ":memory:",
			opts: []Option{
				WithMaxConnections(5),
				WithBusyTimeout(10 * time.Second),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := New(tt.path, tt.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				defer func() {
					if closeErr := db.Close(); closeErr != nil {
						t.Errorf("Failed to close database: %v", closeErr)
					}
				}()

				// Verify connection is working
				var result int
				err := db.QueryRowContext(context.Background(), "SELECT 1").Scan(&result)
				if err != nil {
					t.Errorf("Failed to query database: %v", err)
				}
				if result != 1 {
					t.Errorf("Expected 1, got %d", result)
				}
			}
		})
	}
}

func TestNewAutomaticInit(t *testing.T) {
	// Create a temporary database file
	tmpfile, err := os.CreateTemp("", "test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	if closeErr := tmpfile.Close(); closeErr != nil {
		t.Fatalf("Failed to close temp file: %v", closeErr)
	}
	defer func() {
		if removeErr := os.Remove(tmpfile.Name()); removeErr != nil {
			t.Errorf("Failed to remove temp file: %v", removeErr)
		}
	}()

	// Test that database is automatically initialized
	db, err := New(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("Failed to close database: %v", closeErr)
		}
	}()

	// Verify migrations table exists
	var count int
	err = db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='migrations'").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query migrations table: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected migrations table to exist")
	}

	// Verify core tables exist
	tables := []string{"scans", "findings", "suppressions"}
	for _, table := range tables {
		err = db.QueryRowContext(context.Background(),
			"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&count)
		if err != nil {
			t.Fatalf("Failed to query %s table: %v", table, err)
		}
		if count != 1 {
			t.Errorf("Expected %s table to exist", table)
		}
	}
}

func TestInTransaction(t *testing.T) {
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

	// Test successful transaction
	err = db.InTransaction(ctx, func(tx *sql.Tx) error {
		_, txErr := tx.ExecContext(ctx, "CREATE TABLE test_table (id INTEGER)")
		return txErr
	})
	if err != nil {
		t.Errorf("InTransaction() error = %v", err)
	}

	// Verify table was created
	var count int
	err = db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='test_table'").Scan(&count)
	if err != nil || count != 1 {
		t.Errorf("Expected test_table to exist")
	}

	// Test failed transaction (rollback)
	err = db.InTransaction(ctx, func(tx *sql.Tx) error {
		_, txErr := tx.ExecContext(ctx, "CREATE TABLE test_table2 (id INTEGER)")
		if txErr != nil {
			return txErr
		}
		// Force an error
		return fmt.Errorf("forced error")
	})
	if err == nil {
		t.Errorf("Expected error from transaction")
	}

	// Verify table was NOT created due to rollback
	err = db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='test_table2'").Scan(&count)
	if err != nil || count != 0 {
		t.Errorf("Expected test_table2 to NOT exist due to rollback")
	}
}

func TestConcurrentAccess(t *testing.T) {
	// Skip this test for in-memory SQLite as it doesn't handle
	// concurrent writes well in shared cache mode
	t.Skip("Skipping concurrent write test for in-memory SQLite")
}

func TestOptions(t *testing.T) {
	db := &DB{
		maxConns:    10,
		busyTimeout: 5 * time.Second,
	}

	// Test WithMaxConnections
	opt := WithMaxConnections(20)
	opt(db)
	if db.maxConns != 20 {
		t.Errorf("Expected maxConns=20, got %d", db.maxConns)
	}

	// Test WithBusyTimeout
	opt = WithBusyTimeout(30 * time.Second)
	opt(db)
	if db.busyTimeout != 30*time.Second {
		t.Errorf("Expected busyTimeout=30s, got %v", db.busyTimeout)
	}
}
