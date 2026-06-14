package storage

import (
	"context"
	"fmt"
	"io/fs"
	"log"
	"sort"
	"strings"

	"github.com/jmoiron/sqlx"
)

// RunMigrations applies any pending SQL migrations from the provided FS.
// Files must be named like "001_init.sql" so that lexicographic sort = apply order.
// Applied versions are tracked in the schema_migrations table.
func RunMigrations(ctx context.Context, db *sqlx.DB, migrationsFS fs.FS) error {
	_, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	if err != nil {
		return fmt.Errorf("migrate: create schema_migrations: %w", err)
	}

	// Load already-applied versions
	var applied []string
	if err := db.SelectContext(ctx, &applied, `SELECT version FROM schema_migrations ORDER BY version`); err != nil {
		return fmt.Errorf("migrate: list applied: %w", err)
	}
	appliedSet := make(map[string]struct{}, len(applied))
	for _, v := range applied {
		appliedSet[v] = struct{}{}
	}

	// Collect and sort .sql files
	entries, err := fs.ReadDir(migrationsFS, ".")
	if err != nil {
		return fmt.Errorf("migrate: read dir: %w", err)
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	// Apply pending migrations inside individual transactions
	for _, name := range files {
		if _, ok := appliedSet[name]; ok {
			continue
		}

		data, err := fs.ReadFile(migrationsFS, name)
		if err != nil {
			return fmt.Errorf("migrate: read %s: %w", name, err)
		}

		tx, err := db.BeginTxx(ctx, nil)
		if err != nil {
			return fmt.Errorf("migrate: begin tx for %s: %w", name, err)
		}

		if _, err := tx.ExecContext(ctx, string(data)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migrate: exec %s: %w", name, err)
		}

		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, name); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migrate: record %s: %w", name, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("migrate: commit %s: %w", name, err)
		}

		log.Printf("migration applied: %s", name)
	}

	return nil
}
