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
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// Open connects to Postgres using a GORM dialector built from dsn.
func Open(dsn string) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		return nil, fmt.Errorf("database: open postgres: %w", err)
	}
	return db, nil
}

// ApplyPoolLimits configures the underlying *sql.DB connection pool. Each
// binary owns its own pool, so bounding open/idle connections and capping
// connection lifetime keeps a fleet of replicas from exhausting Postgres'
// max_connections and lets long-lived workers pick up failovers. A non-positive
// maxOpen/maxIdle leaves the database/sql default in place; a non-positive
// maxLifetime leaves connections un-aged.
func ApplyPoolLimits(db *gorm.DB, maxOpen, maxIdle int, maxLifetime time.Duration) error {
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
	return nil
}

// OpenSQLite opens an in-process SQLite database. Pass ":memory:" for tests.
func OpenSQLite(path string) (*gorm.DB, error) {
	db, err := gorm.Open(gormsqlite.Open(path), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
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
