// Package database opens the control-plane database and applies schema. Two
// paths exist deliberately:
//
//   - Open: a Postgres pool for production / the docker-compose stack, driven
//     by the ordered SQL migrations in internal/migrations.
//   - OpenSQLite / AutoMigrate: an in-process SQLite database used by unit
//     tests so they need no external Postgres.
//
// GORM auto-migrate (AutoMigrate) and the SQL migrations are kept consistent:
// the models in internal/models are the source of truth, and the SQL files
// reproduce that schema for production where we want explicit, reviewable DDL.
package database

import (
	"fmt"
	"time"

	gormsqlite "github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// Open connects to Postgres using a GORM dialector built from dsn. The pool is
// wired for Row-Level Security tenant isolation: each operation's connection has
// its app.workspace_id GUC set from the request context (see rls.go), which the
// tenant_isolation policies from migration 0024 enforce against. Callers that
// pass an unscoped context (workers, migrations) are unaffected.
func Open(dsn string) (*gorm.DB, error) {
	return openPostgresRLS(dsn, &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
		// Translate driver-specific errors (e.g. unique violations) to GORM's
		// portable sentinels so callers can detect them with errors.Is across
		// the Postgres and SQLite backends — used by the PAM command-seq retry.
		TranslateError: true,
	})
}

// ApplyPoolLimits configures the underlying *sql.DB connection pool. Each
// binary owns its own pool, so bounding open/idle connections and capping
// connection lifetime keeps a fleet of replicas from exhausting Postgres'
// max_connections and lets long-lived workers pick up failovers. A non-positive
// maxOpen/maxIdle leaves the database/sql default in place; a non-positive
// maxLifetime leaves connections un-aged.
func ApplyPoolLimits(db *gorm.DB, maxOpen, maxIdle int, maxLifetime time.Duration) error {
	return ApplyPoolLimitsWithIdle(db, maxOpen, maxIdle, maxLifetime, 0)
}

// ApplyPoolLimitsWithIdle is ApplyPoolLimits plus a connection idle-time cap.
// maxIdleTime closes a connection that has sat idle that long, letting the pool
// shrink BELOW maxIdle during quiet periods rather than holding warm
// connections open — the NoOps lever for a many-tenant fleet whose traffic is
// bursty and diurnal, so a quiet control-plane replica returns its connections
// to Postgres instead of reserving max_connections headroom it is not using. A
// non-positive maxIdleTime leaves idle connections un-aged (identical to
// ApplyPoolLimits), so existing callers are unaffected.
func ApplyPoolLimitsWithIdle(db *gorm.DB, maxOpen, maxIdle int, maxLifetime, maxIdleTime time.Duration) error {
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("database: resolve pool: %w", err)
	}
	if maxOpen > 0 {
		sqlDB.SetMaxOpenConns(maxOpen)
	}
	if maxIdle > 0 {
		sqlDB.SetMaxIdleConns(maxIdle)
	}
	if maxLifetime > 0 {
		sqlDB.SetConnMaxLifetime(maxLifetime)
	}
	if maxIdleTime > 0 {
		sqlDB.SetConnMaxIdleTime(maxIdleTime)
	}
	return nil
}

// OpenSQLite opens an in-process SQLite database. Pass ":memory:" for tests.
func OpenSQLite(path string) (*gorm.DB, error) {
	db, err := gorm.Open(gormsqlite.Open(path), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
		// Match Open: surface unique violations as gorm.ErrDuplicatedKey so the
		// PAM command-seq retry behaves identically under the test backend.
		TranslateError: true,
	})
	if err != nil {
		return nil, fmt.Errorf("database: open sqlite: %w", err)
	}
	return db, nil
}

// AutoMigrate creates/updates tables for every model. Used by tests and by the
// dev boot path; production uses the SQL migration runner.
func AutoMigrate(db *gorm.DB) error {
	if err := db.AutoMigrate(models.All()...); err != nil {
		return fmt.Errorf("database: auto-migrate: %w", err)
	}
	return nil
}
