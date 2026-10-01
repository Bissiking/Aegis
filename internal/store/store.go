// Package store implements the persistence layer for Aegis.
//
// The MVP uses SQLite (pure Go driver). All SQL goes through parameterised
// queries. The schema and the query layer are intentionally kept free of
// business logic so a future switch to PostgreSQL only requires a new driver
// and dialect adaptation, not a rewrite of the domain services.
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Store wraps the SQL database.
type Store struct {
	db      *sql.DB
	path    string
	nowFunc func() time.Time
}

// Open opens (and creating if needed) a SQLite database, applies pending
// migrations and returns a ready Store.
func Open(path string) (*Store, error) {
	var dsn string
	if path == ":memory:" {
		// A unique shared-cache name guarantees that two Open(":memory:")
		// calls in the same process do not share data.
		suffix, err := randomSuffix()
		if err != nil {
			return nil, err
		}
		dsn = "file:aegis-" + suffix + "?mode=memory&cache=shared&_pragma=foreign_keys(1)"
	} else {
		if dir := filepath.Dir(path); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return nil, fmt.Errorf("create database directory: %w", err)
			}
		}
		dsn = "file:" + strings.ReplaceAll(path, "\\", "/") +
			"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)

	s := &Store{db: db, path: path, nowFunc: time.Now}
	if err := s.Migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func randomSuffix() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// DB exposes the underlying handle for tightly-scoped transactions.
func (s *Store) DB() *sql.DB { return s.db }

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Now returns the current time (overridable in tests).
func (s *Store) Now() time.Time { return s.nowFunc().UTC() }

// SetNow overrides the clock (tests only).
func (s *Store) SetNow(f func() time.Time) { s.nowFunc = f }

// Migration is a single versioned schema change.
type Migration struct {
	Version int
	Name    string
	SQL     string
}

// LoadMigrations reads the embedded, ordered migrations.
func LoadMigrations() ([]Migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	var out []Migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		base := strings.TrimSuffix(e.Name(), ".sql")
		idx := strings.Index(base, "_")
		if idx < 0 {
			return nil, fmt.Errorf("migration %q must be named NNNN_name.sql", e.Name())
		}
		v, err := strconv.Atoi(base[:idx])
		if err != nil {
			return nil, fmt.Errorf("migration %q: %w", e.Name(), err)
		}
		body, err := migrationFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, Migration{Version: v, Name: base[idx+1:], SQL: string(body)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// Migrate applies every pending migration inside a transaction each.
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		applied_at INTEGER NOT NULL
	)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	applied := map[int]bool{}
	rows, err := s.db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		applied[v] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	migs, err := LoadMigrations()
	if err != nil {
		return err
	}
	for _, m := range migs {
		if applied[m.Version] {
			continue
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %04d_%s: %w", m.Version, m.Name, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations(version, name, applied_at) VALUES(?,?,?)`,
			m.Version, m.Name, time.Now().Unix()); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// PendingMigrations reports how many migrations would still be applied.
func (s *Store) PendingMigrations(ctx context.Context) (int, error) {
	migs, err := LoadMigrations()
	if err != nil {
		return 0, err
	}
	var n int
	rows, err := s.db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	applied := map[int]bool{}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return 0, err
		}
		applied[v] = true
	}
	for _, m := range migs {
		if !applied[m.Version] {
			n++
		}
	}
	return n, nil
}

// Tx runs fn inside a transaction.
func (s *Store) Tx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}
