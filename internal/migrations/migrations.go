// Package migrations applies the ordered SQL schema migrations for the
// ShieldNet Access control plane. SQL files live next to this file as
// NNNN_name.sql and are embedded into the binary so a single artifact can
// migrate a fresh Postgres database with no external files.
//
// The runner is idempotent: it records applied versions in a
// schema_migrations table and skips anything already applied, so it is safe to
// run on every boot and from the migrate CLI.
package migrations

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"strings"
)

//go:embed *.sql
var files embed.FS

// Migration is one ordered SQL file.
type Migration struct {
	Version string
	Name    string
	SQL     string
}

// Load reads and sorts every embedded migration by filename (which begins with
// a zero-padded version, so lexical order == apply order).
func Load() ([]Migration, error) {
	entries, err := files.ReadDir(".")
	if err != nil {
		return nil, err
	}
	var out []Migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		b, err := files.ReadFile(e.Name())
		if err != nil {
			return nil, err
		}
		version, name := splitName(e.Name())
		out = append(out, Migration{Version: version, Name: name, SQL: string(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

func splitName(filename string) (version, name string) {
	base := strings.TrimSuffix(filename, ".sql")
	if i := strings.Index(base, "_"); i > 0 {
		return base[:i], base[i+1:]
	}
	return base, base
}

// Run applies every migration not yet recorded in schema_migrations, inside a
// per-migration transaction. It is safe to call repeatedly.
func Run(ctx context.Context, db *sql.DB) (applied []string, err error) {
	if _, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY,
		name    TEXT NOT NULL,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`); err != nil {
		return nil, fmt.Errorf("migrations: ensure schema_migrations: %w", err)
	}

	migs, err := Load()
	if err != nil {
		return nil, err
	}

	for _, m := range migs {
		var exists bool
		if err = db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)`, m.Version).Scan(&exists); err != nil {
			return applied, fmt.Errorf("migrations: check %s: %w", m.Version, err)
		}
		if exists {
			continue
		}
		tx, txErr := db.BeginTx(ctx, nil)
		if txErr != nil {
			return applied, txErr
		}
		if _, err = tx.ExecContext(ctx, m.SQL); err != nil {
			_ = tx.Rollback()
			return applied, fmt.Errorf("migrations: apply %s_%s: %w", m.Version, m.Name, err)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, name) VALUES ($1, $2)`, m.Version, m.Name); err != nil {
			_ = tx.Rollback()
			return applied, fmt.Errorf("migrations: record %s: %w", m.Version, err)
		}
		if commitErr := tx.Commit(); commitErr != nil {
			return applied, commitErr
		}
		applied = append(applied, m.Version+"_"+m.Name)
	}
	return applied, nil
}
