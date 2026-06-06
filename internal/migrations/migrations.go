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
	"errors"
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

// advisoryLockKey is a fixed, application-specific key for the Postgres
// session-level advisory lock that serializes migration runs. Derived once from
// the constant string "fishbone-access:migrations" so every replica computes
// the same value; the exact number is arbitrary but must never change.
const advisoryLockKey int64 = 0x5348_4E41_4343_0001

// Run applies every migration not yet recorded in schema_migrations, inside a
// per-migration transaction. It is safe to call repeatedly and from multiple
// instances concurrently: a Postgres session-level advisory lock serializes
// the whole run so two replicas booting together cannot race to apply the same
// version (which would otherwise crash the loser on the schema_migrations
// primary-key insert).
func Run(ctx context.Context, db *sql.DB) (applied []string, err error) {
	// Pin a single connection for the lifetime of the run: a session-level
	// advisory lock is held by the backend session, so lock, migrate, and
	// unlock must all execute on the same physical connection.
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("migrations: acquire connection: %w", err)
	}
	defer func() {
		// Release the advisory lock explicitly: returning a *sql.Conn to the
		// pool via Close() does NOT end the backend session, so a session-level
		// lock would otherwise leak until that pooled connection is discarded.
		// Use a non-cancellable context so the unlock still runs even if ctx
		// was cancelled mid-migration. Closing the conn is the final backstop.
		if _, uerr := conn.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, advisoryLockKey); uerr != nil {
			err = errors.Join(err, fmt.Errorf("migrations: release advisory lock: %w", uerr))
		}
		if cerr := conn.Close(); cerr != nil {
			err = errors.Join(err, fmt.Errorf("migrations: close connection: %w", cerr))
		}
	}()

	if _, err = conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, advisoryLockKey); err != nil {
		return nil, fmt.Errorf("migrations: acquire advisory lock: %w", err)
	}

	if _, err = conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
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
		if err = conn.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)`, m.Version).Scan(&exists); err != nil {
			return applied, fmt.Errorf("migrations: check %s: %w", m.Version, err)
		}
		if exists {
			continue
		}
		tx, txErr := conn.BeginTx(ctx, nil)
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
