package database

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Migration represents a database migration.
type Migration struct {
	Name    string
	SQL     string
	Version int
}

// Migrate runs all pending migrations.
func (db *DB) Migrate(ctx context.Context) error {
	// Create migrations table if it doesn't exist
	if err := db.createMigrationsTable(ctx); err != nil {
		return fmt.Errorf("creating migrations table: %w", err)
	}

	// Get current version
	currentVersion, err := db.getCurrentVersion(ctx)
	if err != nil {
		return fmt.Errorf("getting current version: %w", err)
	}

	// Load all migrations
	migrations, err := loadMigrations()
	if err != nil {
		return fmt.Errorf("loading migrations: %w", err)
	}

	// Apply pending migrations
	for _, migration := range migrations {
		if migration.Version <= currentVersion {
			continue
		}

		if err := db.applyMigration(ctx, migration); err != nil {
			return fmt.Errorf("applying migration %d (%s): %w", migration.Version, migration.Name, err)
		}
	}

	return nil
}

// createMigrationsTable creates the migrations tracking table.
func (db *DB) createMigrationsTable(ctx context.Context) error {
	query := `
	CREATE TABLE IF NOT EXISTS migrations (
		version INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`

	_, err := db.ExecContext(ctx, query)
	return err
}

// getCurrentVersion returns the current migration version.
func (db *DB) getCurrentVersion(ctx context.Context) (int, error) {
	var version sql.NullInt64
	query := `SELECT MAX(version) FROM migrations`

	err := db.QueryRowContext(ctx, query).Scan(&version)
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	}

	if version.Valid {
		return int(version.Int64), nil
	}

	return 0, nil
}

// applyMigration applies a single migration.
func (db *DB) applyMigration(ctx context.Context, migration Migration) error {
	return db.InTransaction(ctx, func(tx *sql.Tx) error {
		// Execute migration SQL
		if _, err := tx.ExecContext(ctx, migration.SQL); err != nil {
			return fmt.Errorf("executing migration SQL: %w", err)
		}

		// Record migration
		query := `INSERT INTO migrations (version, name) VALUES (?, ?)`
		if _, err := tx.ExecContext(ctx, query, migration.Version, migration.Name); err != nil {
			return fmt.Errorf("recording migration: %w", err)
		}

		return nil
	})
}

// loadMigrations loads all migration files from embedded filesystem.
func loadMigrations() ([]Migration, error) {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return nil, fmt.Errorf("reading migrations directory: %w", err)
	}

	migrations := make([]Migration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}

		migration, err := parseMigration(entry)
		if err != nil {
			return nil, fmt.Errorf("parsing migration %s: %w", entry.Name(), err)
		}

		migrations = append(migrations, migration)
	}

	// Sort migrations by version
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	return migrations, nil
}

// parseMigration parses a migration file.
func parseMigration(entry fs.DirEntry) (Migration, error) {
	// Parse filename: 001_initial.sql
	parts := strings.SplitN(entry.Name(), "_", 2)
	if len(parts) != 2 {
		return Migration{}, fmt.Errorf("invalid migration filename: %s", entry.Name())
	}

	version, err := strconv.Atoi(parts[0])
	if err != nil {
		return Migration{}, fmt.Errorf("parsing version number: %w", err)
	}

	name := strings.TrimSuffix(parts[1], ".sql")

	// Read SQL content
	content, err := migrationsFS.ReadFile("migrations/" + entry.Name())
	if err != nil {
		return Migration{}, fmt.Errorf("reading migration file: %w", err)
	}

	return Migration{
		Version: version,
		Name:    name,
		SQL:     string(content),
	}, nil
}

// GetMigrationVersion returns the current migration version.
func (db *DB) GetMigrationVersion(ctx context.Context) (int, error) {
	return db.getCurrentVersion(ctx)
}
