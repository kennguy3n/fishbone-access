// pgx.go is the pgxpool adapter: a direct github.com/jackc/pgx/v5 backend for
// the two repository contracts that begin the GORM→pgx migration — workspace
// configuration reads and audit-log appends. It exists alongside the GORM
// path in this same package (Open/OpenSQLite) so the migration is incremental:
// a binary opens a *pgxpool.Pool with OpenPool, constructs the pgx repositories
// here, and injects them where a GORM handle was used before. The GORM and pgx
// implementations honour an identical contract — same query semantics, same
// soft-delete scoping, same gorm.ErrRecordNotFound sentinel on a miss, and (for
// audit) the same per-workspace advisory lock and SHA-256 hash chain via the
// shared auditchain package — so the two can run side by side against the same
// database without diverging.
//
// Tenant isolation is preserved exactly as the GORM path enforces it: this
// adapter never exposes an unscoped mutation, the workspace lookups are the
// authoritative tenant→workspace resolution that RequireTenant feeds every
// request through, and the audit append is keyed on a verified workspace id.
// No method accepts a caller-supplied workspace filter that could widen scope.
package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/auditchain"
)

// ErrValidation is returned for malformed audit input (missing workspace id or
// action). It mirrors the validation the GORM appender performs so a caller
// switching backends sees the same fail-fast behaviour on bad input.
var ErrValidation = errors.New("database: validation")

// OpenPool opens a pgxpool connected to dsn and verifies it with a ping so a
// bad DSN or unreachable database is a hard startup error rather than a failure
// on first query. The pool bounds mirror database/sql's on the GORM path
// (ApplyPoolLimits): a non-positive maxConns leaves pgx's default (4×NumCPU,
// min 4) in place; a non-positive lifetime/idle leaves connections un-aged. The
// caller owns the returned pool and MUST Close it on shutdown.
func OpenPool(ctx context.Context, dsn string, maxConns int32, maxConnLifetime, maxConnIdleTime time.Duration) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("database: parse pgx dsn: %w", err)
	}
	if maxConns > 0 {
		cfg.MaxConns = maxConns
	}
	if maxConnLifetime > 0 {
		cfg.MaxConnLifetime = maxConnLifetime
	}
	if maxConnIdleTime > 0 {
		cfg.MaxConnIdleTime = maxConnIdleTime
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("database: open pgx pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database: ping pgx pool: %w", err)
	}
	return pool, nil
}

// WorkspaceConfig is the read view of a row in the workspaces table — the
// per-tenant configuration record. DataResidency and SSOConnectionID are empty
// strings when their (nullable) columns are NULL; all reads return live rows
// only (deleted_at IS NULL), matching GORM's default soft-delete scope.
type WorkspaceConfig struct {
	ID              uuid.UUID
	Name            string
	IAMCoreTenantID string
	Plan            string
	DataResidency   string
	DefaultLocale   string
	SSOConnectionID string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// WorkspaceConfigStore is the workspace-configuration repository contract. It
// is the set of workspace reads the control plane performs today, lifted off
// the concrete *gorm.DB so either backend can satisfy it:
//
//   - WorkspaceIDByTenant: the authoritative tenant→workspace resolution that
//     RequireTenant runs on every authenticated request.
//   - Workspace: the full config row, read by the PAM step-up gate and
//     connect-token mint to recover a workspace's iam-core tenant id.
//   - WorkspaceIDs: the live-workspace fan-out list used by the expiry and
//     orphan-reconciliation sweeps.
//
// Every method is workspace- or tenant-keyed; none can widen scope.
type WorkspaceConfigStore interface {
	WorkspaceIDByTenant(ctx context.Context, tenantID string) (uuid.UUID, error)
	Workspace(ctx context.Context, id uuid.UUID) (WorkspaceConfig, error)
	WorkspaceIDs(ctx context.Context) ([]uuid.UUID, error)
}

// AuditInput is the backend-independent description of an action to append to a
// workspace's tamper-evident audit hash chain. It mirrors lifecycle.AuditInput
// but lives here so the adapter has no dependency on the lifecycle service
// (which would form an import cycle through lifecycle's tests); the two structs
// carry identical fields and the chain bookkeeping is filled in by the appender
// using the shared auditchain primitives, so a row written through this adapter
// is byte-for-byte what the GORM appender would write.
type AuditInput struct {
	WorkspaceID uuid.UUID
	Actor       string
	Action      string
	TargetRef   string
	Metadata    []byte
}

// AuditAppender is the audit-log repository contract: append one event to a
// workspace's hash chain in its own transaction. It is the standalone-append
// half of the GORM lifecycle.AppendAudit entrypoint, reimplemented on pgx with
// identical semantics (advisory lock, soft-delete-blind head read, chain_seq +
// SHA-256 linking) so a PAM standalone audit can run on either backend and land
// in the same chain.
type AuditAppender interface {
	AppendAudit(ctx context.Context, now time.Time, in AuditInput) error
}

// PgxWorkspaceConfigRepo is the pgxpool-backed WorkspaceConfigStore.
type PgxWorkspaceConfigRepo struct {
	pool *pgxpool.Pool
}

// NewPgxWorkspaceConfigRepo builds the pgx workspace-config repository.
func NewPgxWorkspaceConfigRepo(pool *pgxpool.Pool) *PgxWorkspaceConfigRepo {
	return &PgxWorkspaceConfigRepo{pool: pool}
}

var _ WorkspaceConfigStore = (*PgxWorkspaceConfigRepo)(nil)

// WorkspaceIDByTenant resolves the workspace UUID for a verified iam-core tenant
// id, returning gorm.ErrRecordNotFound when no live workspace matches — the same
// sentinel the GORM path returns, so RequireTenant's fail-closed 403 branch is
// unchanged. iam_core_tenant_id is UNIQUE, so at most one row matches.
func (r *PgxWorkspaceConfigRepo) WorkspaceIDByTenant(ctx context.Context, tenantID string) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.pool.QueryRow(ctx,
		`SELECT id FROM workspaces WHERE iam_core_tenant_id = $1 AND deleted_at IS NULL`,
		tenantID,
	).Scan(&id)
	switch {
	case err == nil:
		return id, nil
	case errors.Is(err, pgx.ErrNoRows):
		return uuid.Nil, gorm.ErrRecordNotFound
	default:
		return uuid.Nil, fmt.Errorf("database: resolve workspace by tenant: %w", err)
	}
}

// Workspace returns the full configuration row for a workspace id, or
// gorm.ErrRecordNotFound when no live row matches.
func (r *PgxWorkspaceConfigRepo) Workspace(ctx context.Context, id uuid.UUID) (WorkspaceConfig, error) {
	var ws WorkspaceConfig
	// Only data_residency and sso_connection_id are nullable in the schema
	// (0001_init.sql), so they are scanned through *string and a NULL maps to
	// the zero value exactly as GORM does. name, plan and default_locale are
	// NOT NULL in the migration — default_locale is `TEXT NOT NULL DEFAULT 'en'`
	// — so they scan straight into string; the SQL migrations are authoritative
	// here (no AutoMigrate in prod), not the GORM struct tags.
	var dataResidency, ssoConnectionID *string
	err := r.pool.QueryRow(ctx,
		`SELECT id, name, iam_core_tenant_id, plan, data_residency, default_locale, sso_connection_id, created_at, updated_at
		   FROM workspaces
		  WHERE id = $1 AND deleted_at IS NULL`,
		id,
	).Scan(&ws.ID, &ws.Name, &ws.IAMCoreTenantID, &ws.Plan, &dataResidency, &ws.DefaultLocale, &ssoConnectionID, &ws.CreatedAt, &ws.UpdatedAt)
	switch {
	case err == nil:
		if dataResidency != nil {
			ws.DataResidency = *dataResidency
		}
		if ssoConnectionID != nil {
			ws.SSOConnectionID = *ssoConnectionID
		}
		return ws, nil
	case errors.Is(err, pgx.ErrNoRows):
		return WorkspaceConfig{}, gorm.ErrRecordNotFound
	default:
		return WorkspaceConfig{}, fmt.Errorf("database: read workspace: %w", err)
	}
}

// WorkspaceIDs lists every live workspace id. The sweeps that consume it are
// idempotent and workspace-scoped, so the unordered set is sufficient; the
// query is ordered by id for deterministic output.
func (r *PgxWorkspaceConfigRepo) WorkspaceIDs(ctx context.Context) ([]uuid.UUID, error) {
	rows, err := r.pool.Query(ctx, `SELECT id FROM workspaces WHERE deleted_at IS NULL ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("database: list workspace ids: %w", err)
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("database: scan workspace id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("database: iterate workspace ids: %w", err)
	}
	return ids, nil
}

// PgxAuditRepo is the pgxpool-backed AuditAppender.
type PgxAuditRepo struct {
	pool *pgxpool.Pool
}

// NewPgxAuditRepo builds the pgx audit repository.
func NewPgxAuditRepo(pool *pgxpool.Pool) *PgxAuditRepo {
	return &PgxAuditRepo{pool: pool}
}

var _ AuditAppender = (*PgxAuditRepo)(nil)

// AppendAudit writes one tamper-evident audit event in its own transaction,
// reproducing the GORM lifecycle.appendAudit semantics exactly:
//
//  1. A per-workspace advisory lock (auditchain.LockKey) serialises appends so
//     the head-read/insert pair is atomic and the chain cannot fork. The lock
//     is transaction-scoped and released on commit/rollback.
//  2. The chain head is the row with the greatest chain_seq, read WITHOUT a
//     soft-delete filter (matching GORM's Unscoped()) so a should-never-happen
//     soft-deleted tail cannot be skipped and orphan the chain.
//  3. The row is a version-1 (canonical) event: the timestamp is truncated to
//     UTC microseconds and the metadata is canonicalised (auditchain) BEFORE it
//     is both hashed and stored, so the row recomputes byte-for-byte on read —
//     chain_hash = auditchain.CanonicalHash(...) and chain_hash_version = 1 —
//     and the next row takes prev_seq + 1.
//
// This is the identical pre-image, version stamp and persisted shape the GORM
// appender writes, so a row written through this adapter is byte-for-byte what
// the GORM path would write into the same workspace chain, and the compliance
// verifier recomputes it (not merely linkage-checks it). The id is generated
// client-side (uuid.New, matching the models.Base BeforeCreate hook) and empty
// metadata is stored as SQL NULL (matching datatypes.JSON's Valuer).
func (r *PgxAuditRepo) AppendAudit(ctx context.Context, now time.Time, in AuditInput) error {
	if in.WorkspaceID == uuid.Nil {
		return fmt.Errorf("%w: audit event requires a workspace id", ErrValidation)
	}
	if in.Action == "" {
		return fmt.Errorf("%w: audit event requires an action", ErrValidation)
	}

	// Normalise the timestamp and metadata to their canonical, persisted form
	// BEFORE hashing so the stored row recomputes exactly (see auditchain).
	now = now.UTC().Truncate(time.Microsecond)
	canonMeta := auditchain.CanonicalMetadata(in.Metadata)

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("database: begin audit tx: %w", err)
	}
	// Rollback is a no-op once the tx has committed; deferring it guarantees the
	// connection is released on every early-return error path below.
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, auditchain.LockKey(in.WorkspaceID)); err != nil {
		return fmt.Errorf("database: lock workspace: %w", err)
	}

	var prevHash string
	var prevSeq int64
	err = tx.QueryRow(ctx,
		`SELECT chain_hash, chain_seq FROM audit_events WHERE workspace_id = $1 ORDER BY chain_seq DESC LIMIT 1`,
		in.WorkspaceID,
	).Scan(&prevHash, &prevSeq)
	switch {
	case err == nil:
		// prevHash and prevSeq are set from the current head.
	case errors.Is(err, pgx.ErrNoRows):
		prevHash, prevSeq = "", 0
	default:
		return fmt.Errorf("database: read audit chain head: %w", err)
	}

	chainHash := auditchain.CanonicalHash(prevHash, in.WorkspaceID, in.Action, in.TargetRef, canonMeta, now)

	// Store the canonical metadata bytes (NULL when empty) so the persisted
	// jsonb pre-image matches what was hashed; storing the caller's raw bytes
	// would let jsonb re-order keys and break the recompute.
	var metadata any
	if len(canonMeta) > 0 {
		metadata = string(canonMeta)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO audit_events
		   (id, workspace_id, chain_seq, actor, action, target_ref, metadata, prev_hash, chain_hash, chain_hash_version, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10, $11, $12)`,
		uuid.New(), in.WorkspaceID, prevSeq+1, in.Actor, in.Action, in.TargetRef, metadata, prevHash, chainHash, auditchain.HashVersion, now, now,
	); err != nil {
		return fmt.Errorf("database: insert audit event: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("database: commit audit tx: %w", err)
	}
	return nil
}

// GormWorkspaceConfigRepo is the GORM-backed WorkspaceConfigStore. It is the
// drop-in used by the SQLite unit-test path and by degraded boots that have a
// *gorm.DB but no pgx pool, so RequireTenant and the sweeps can depend on the
// WorkspaceConfigStore interface uniformly while the pgx migration proceeds
// table by table. Its query semantics are identical to the pgx implementation.
type GormWorkspaceConfigRepo struct {
	db *gorm.DB
}

// NewGormWorkspaceConfigRepo builds the GORM workspace-config repository.
func NewGormWorkspaceConfigRepo(db *gorm.DB) *GormWorkspaceConfigRepo {
	return &GormWorkspaceConfigRepo{db: db}
}

var _ WorkspaceConfigStore = (*GormWorkspaceConfigRepo)(nil)

// WorkspaceIDByTenant resolves the workspace UUID for a verified tenant id. The
// default GORM scope filters deleted_at IS NULL, matching the pgx query.
func (r *GormWorkspaceConfigRepo) WorkspaceIDByTenant(ctx context.Context, tenantID string) (uuid.UUID, error) {
	var ws struct{ ID uuid.UUID }
	err := r.db.WithContext(ctx).
		Model(&workspacesModel{}).
		Select("id").
		Where("iam_core_tenant_id = ?", tenantID).
		Take(&ws).Error
	if err != nil {
		return uuid.Nil, err
	}
	return ws.ID, nil
}

// Workspace returns the full configuration row for a workspace id.
func (r *GormWorkspaceConfigRepo) Workspace(ctx context.Context, id uuid.UUID) (WorkspaceConfig, error) {
	var row workspacesModel
	if err := r.db.WithContext(ctx).Where("id = ?", id).Take(&row).Error; err != nil {
		return WorkspaceConfig{}, err
	}
	return WorkspaceConfig{
		ID:              row.ID,
		Name:            row.Name,
		IAMCoreTenantID: row.IAMCoreTenantID,
		Plan:            row.Plan,
		DataResidency:   row.DataResidency,
		DefaultLocale:   row.DefaultLocale,
		SSOConnectionID: row.SSOConnectionID,
		CreatedAt:       row.CreatedAt,
		UpdatedAt:       row.UpdatedAt,
	}, nil
}

// WorkspaceIDs lists every live workspace id, ordered by id to match the pgx
// implementation's deterministic output.
func (r *GormWorkspaceConfigRepo) WorkspaceIDs(ctx context.Context) ([]uuid.UUID, error) {
	var ids []uuid.UUID
	if err := r.db.WithContext(ctx).
		Model(&workspacesModel{}).
		Order("id").
		Pluck("id", &ids).Error; err != nil {
		return nil, err
	}
	return ids, nil
}

// GormAuditRepo is the GORM-backed AuditAppender — the standalone-append
// counterpart to PgxAuditRepo selected when ACCESS_DATABASE_DRIVER=gorm (and the
// backend used on the SQLite unit-test path). It writes into the SAME
// per-workspace chain with byte-identical semantics:
//
//   - the per-workspace advisory lock on Postgres (auditchain.LockKey),
//   - the soft-delete-blind head read by chain_seq (Unscoped, matching the
//     lifecycle appender so a should-never-happen soft-deleted tail cannot fork
//     the chain),
//   - a version-1 canonical row whose timestamp and metadata are normalised
//     before hashing via the shared auditchain primitives.
//
// A row written here is therefore indistinguishable from one written by
// PgxAuditRepo or lifecycle.AppendAudit, so the two drivers coexist on one chain
// and a deployment can switch between them without a verifier-visible seam. The
// logic is reimplemented on *gorm.DB rather than delegating to the lifecycle
// service to keep this package free of an import cycle (lifecycle's in-package
// tests import this package), the same pattern GormWorkspaceConfigRepo follows.
//
// Unlike GormWorkspaceConfigRepo — which defines a local row struct and relies
// on a drift test to stay aligned with internal/models — this repo deliberately
// binds to the canonical models.AuditEvent. The audit row is a security-critical
// tamper-evident record (chain_seq, prev_hash, chain_hash, chain_hash_version)
// that must agree exactly with the lifecycle appender, so coupling to the single
// source of truth removes the drift surface entirely (the import is acyclic:
// internal/models does not import this package).
type GormAuditRepo struct {
	db *gorm.DB
}

// NewGormAuditRepo builds the GORM audit repository.
func NewGormAuditRepo(db *gorm.DB) *GormAuditRepo { return &GormAuditRepo{db: db} }

var _ AuditAppender = (*GormAuditRepo)(nil)

// AppendAudit writes one tamper-evident audit event in its own transaction with
// the same canonical pre-image and version stamp as PgxAuditRepo.
func (r *GormAuditRepo) AppendAudit(ctx context.Context, now time.Time, in AuditInput) error {
	if in.WorkspaceID == uuid.Nil {
		return fmt.Errorf("%w: audit event requires a workspace id", ErrValidation)
	}
	if in.Action == "" {
		return fmt.Errorf("%w: audit event requires an action", ErrValidation)
	}

	// Normalise the timestamp and metadata to their canonical, persisted form
	// BEFORE hashing so the stored row recomputes exactly (see auditchain).
	now = now.UTC().Truncate(time.Microsecond)
	canonMeta := auditchain.CanonicalMetadata(in.Metadata)

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Serialise concurrent appends in this workspace so the head-read/insert
		// pair is atomic and the chain cannot fork. Postgres only; the SQLite
		// test path serialises writers with a single global write lock.
		if tx.Dialector != nil && tx.Name() == "postgres" {
			if err := tx.WithContext(ctx).Exec("SELECT pg_advisory_xact_lock(?)", auditchain.LockKey(in.WorkspaceID)).Error; err != nil {
				return fmt.Errorf("database: lock workspace: %w", err)
			}
		}

		var prev models.AuditEvent
		prevHash := ""
		var prevSeq int64
		err := tx.WithContext(ctx).
			Unscoped().
			Where("workspace_id = ?", in.WorkspaceID).
			Order("chain_seq desc").
			Limit(1).
			Take(&prev).Error
		switch {
		case err == nil:
			prevHash = prev.ChainHash
			prevSeq = prev.ChainSeq
		case errors.Is(err, gorm.ErrRecordNotFound):
			prevHash, prevSeq = "", 0
		default:
			return fmt.Errorf("database: read audit chain head: %w", err)
		}

		chainHash := auditchain.CanonicalHash(prevHash, in.WorkspaceID, in.Action, in.TargetRef, canonMeta, now)

		// nil datatypes.JSON persists as SQL NULL (its Valuer returns nil for an
		// empty value), matching the pgx path's NULL for empty metadata.
		var stored datatypes.JSON
		if len(canonMeta) > 0 {
			stored = datatypes.JSON(canonMeta)
		}
		row := &models.AuditEvent{
			WorkspaceID:      in.WorkspaceID,
			ChainSeq:         prevSeq + 1,
			Actor:            in.Actor,
			Action:           in.Action,
			TargetRef:        in.TargetRef,
			Metadata:         stored,
			PrevHash:         prevHash,
			ChainHash:        chainHash,
			ChainHashVersion: auditchain.HashVersion,
		}
		row.CreatedAt = now
		row.UpdatedAt = now
		if err := tx.WithContext(ctx).Create(row).Error; err != nil {
			return fmt.Errorf("database: insert audit event: %w", err)
		}
		return nil
	})
}

// workspacesModel is a minimal GORM model bound to the workspaces table for the
// GORM-backed repository. It embeds gorm.Model-style soft-delete via DeletedAt
// so the default scope filters deleted rows exactly as the production
// models.Workspace does, without this adapter importing the models package's
// full graph.
type workspacesModel struct {
	ID              uuid.UUID `gorm:"type:uuid;primaryKey"`
	Name            string
	IAMCoreTenantID string
	Plan            string
	DataResidency   string
	DefaultLocale   string
	SSOConnectionID string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	DeletedAt       gorm.DeletedAt
}

// TableName binds workspacesModel to the workspaces table.
func (workspacesModel) TableName() string { return "workspaces" }
