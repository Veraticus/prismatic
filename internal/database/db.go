// Package database provides SQLite database functionality for Prismatic
package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

// DB represents a database connection with additional functionality.
type DB struct {
	conn        *sql.DB
	path        string
	mu          sync.RWMutex
	maxConns    int
	busyTimeout time.Duration
}

// Option represents a functional option for configuring the database.
type Option func(*DB)

// WithMaxConnections sets the maximum number of open connections.
func WithMaxConnections(n int) Option {
	return func(db *DB) {
		db.maxConns = n
	}
}

// WithBusyTimeout sets the busy timeout for SQLite.
func WithBusyTimeout(timeout time.Duration) Option {
	return func(db *DB) {
		db.busyTimeout = timeout
	}
}

// New creates a new database connection with automatic initialization.
func New(path string, opts ...Option) (*DB, error) {
	db := &DB{
		path:        path,
		maxConns:    10,
		busyTimeout: 5 * time.Second,
	}

	// Apply options
	for _, opt := range opts {
		opt(db)
	}

	// Open database connection
	var connStr string
	if strings.Contains(path, "?") {
		// If path already has query parameters, append with &
		connStr = fmt.Sprintf("%s&_busy_timeout=%d", path, db.busyTimeout.Milliseconds())
	} else {
		// Otherwise, add query parameters with ?
		connStr = fmt.Sprintf("%s?_busy_timeout=%d", path, db.busyTimeout.Milliseconds())
	}

	conn, err := sql.Open("sqlite3", connStr)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// Configure connection pool
	conn.SetMaxOpenConns(db.maxConns)
	conn.SetMaxIdleConns(db.maxConns / 2)
	conn.SetConnMaxLifetime(time.Hour)

	// Apply SQLite optimizations
	pragmas := []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = NORMAL",
		"PRAGMA cache_size = 10000",
		"PRAGMA foreign_keys = ON",
		"PRAGMA temp_store = MEMORY",
	}

	for _, pragma := range pragmas {
		if _, err := conn.Exec(pragma); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("setting %s: %w", pragma, err)
		}
	}

	db.conn = conn

	// Run migrations automatically
	if err := db.Migrate(context.Background()); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	return db, nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if db.conn != nil {
		return db.conn.Close()
	}
	return nil
}

// Conn returns the underlying database connection.
func (db *DB) Conn() *sql.DB {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.conn
}

// BeginTx starts a new transaction with the given context.
func (db *DB) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
	return db.conn.BeginTx(ctx, opts)
}

// ExecContext executes a query that doesn't return rows.
func (db *DB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return db.conn.ExecContext(ctx, query, args...)
}

// QueryContext executes a query that returns rows.
func (db *DB) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return db.conn.QueryContext(ctx, query, args...)
}

// QueryRowContext executes a query that returns at most one row.
func (db *DB) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return db.conn.QueryRowContext(ctx, query, args...)
}

// PrepareContext creates a prepared statement.
func (db *DB) PrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	return db.conn.PrepareContext(ctx, query)
}

// InTransaction executes a function within a database transaction.
func (db *DB) InTransaction(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}

	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("rolling back transaction: %w (original error: %v)", rbErr, err)
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}

	return nil
}

// NewMemoryDB creates an in-memory database for testing.
func NewMemoryDB() (*DB, error) {
	// Use shared cache mode for in-memory database to allow concurrent access
	// This ensures all connections see the same in-memory database
	return New("file::memory:?cache=shared")
}
