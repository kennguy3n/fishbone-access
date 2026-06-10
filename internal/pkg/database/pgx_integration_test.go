//go:build integration

package database_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kennguy3n/fishbone-access/internal/migrations"
	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/auditchain"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
	"gorm.io/gorm"
)

// pgxTestSetup resets ACCESS_TEST_DATABASE_URL to a clean schema, applies the
// production migrations, and returns a GORM handle (the incumbent backend) plus
// a pgxpool (the new adapter) pointed at the same database, so a test can prove
// the two produce identical results. It skips when the env var is unset, the
// same gate the other integration tests use.
func pgxTestSetup(t *testing.T) (context.Context, *gorm.DB, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("ACCESS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("ACCESS_TEST_DATABASE_URL not set; skipping pgx adapter integration test")
	}
	ctx := context.Background()

	gdb, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("open gorm: %v", err)
	}
	sqlDB, err := gdb.DB()
	if err != nil {
		t.Fatalf("sql handle: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	if _, err := sqlDB.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	if _, err := migrations.Run(ctx, sqlDB); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	pool, err := database.OpenPool(ctx, dsn, 10, 0, 0)
	if err != nil {
		t.Fatalf("open pgx pool: %v", err)
	}
	t.Cleanup(pool.Close)

	return ctx, gdb, pool
}

// seedWorkspace inserts one workspace via GORM (the source of truth for the
// row's shape) and returns it.
func seedWorkspace(t *testing.T, gdb *gorm.DB, ws *models.Workspace) *models.Workspace {
	t.Helper()
	if err := gdb.Create(ws).Error; err != nil {
		t.Fatalf("seed workspace: %v", err)
	}
	return ws
}

// TestPgxWorkspaceConfigParity proves the pgx WorkspaceConfigStore returns the
// same results as the GORM-backed one for every read in the contract, including
// the not-found sentinel and soft-delete scoping.
func TestPgxWorkspaceConfigParity(t *testing.T) {
	ctx, gdb, pool := pgxTestSetup(t)
	pgxRepo := database.NewPgxWorkspaceConfigRepo(pool)
	gormRepo := database.NewGormWorkspaceConfigRepo(gdb)

	full := seedWorkspace(t, gdb, &models.Workspace{
		Name:            "acme",
		IAMCoreTenantID: "tenant-acme",
		Plan:            "pro",
		DataResidency:   "eu",
		DefaultLocale:   "fr",
		SSOConnectionID: "sso-123",
	})
	minimal := seedWorkspace(t, gdb, &models.Workspace{
		Name:            "beta",
		IAMCoreTenantID: "tenant-beta",
	})

	// WorkspaceIDByTenant: hit.
	for tenant, want := range map[string]uuid.UUID{
		"tenant-acme": full.ID,
		"tenant-beta": minimal.ID,
	} {
		pgxID, err := pgxRepo.WorkspaceIDByTenant(ctx, tenant)
		if err != nil {
			t.Fatalf("pgx WorkspaceIDByTenant(%s): %v", tenant, err)
		}
		gormID, err := gormRepo.WorkspaceIDByTenant(ctx, tenant)
		if err != nil {
			t.Fatalf("gorm WorkspaceIDByTenant(%s): %v", tenant, err)
		}
		if pgxID != want || gormID != want {
			t.Fatalf("tenant %s: pgx=%s gorm=%s want=%s", tenant, pgxID, gormID, want)
		}
	}

	// WorkspaceIDByTenant: miss returns the SAME sentinel on both backends.
	if _, err := pgxRepo.WorkspaceIDByTenant(ctx, "tenant-missing"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("pgx miss: got %v, want gorm.ErrRecordNotFound", err)
	}
	if _, err := gormRepo.WorkspaceIDByTenant(ctx, "tenant-missing"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("gorm miss: got %v, want gorm.ErrRecordNotFound", err)
	}

	// Workspace: full row mapping, including nullable columns.
	pgxWS, err := pgxRepo.Workspace(ctx, full.ID)
	if err != nil {
		t.Fatalf("pgx Workspace: %v", err)
	}
	gormWS, err := gormRepo.Workspace(ctx, full.ID)
	if err != nil {
		t.Fatalf("gorm Workspace: %v", err)
	}
	if pgxWS != gormWS {
		t.Fatalf("Workspace mismatch:\n pgx=%+v\ngorm=%+v", pgxWS, gormWS)
	}
	if pgxWS.DataResidency != "eu" || pgxWS.SSOConnectionID != "sso-123" || pgxWS.Plan != "pro" || pgxWS.DefaultLocale != "fr" {
		t.Fatalf("pgx Workspace field mapping wrong: %+v", pgxWS)
	}

	// Workspace(minimal): the two genuinely-nullable columns (data_residency,
	// sso_connection_id) are NULL here and must map to "" on both backends; the
	// NOT NULL default_locale carries its 'en' migration default. The pgx and
	// GORM reads must agree on the whole row. (default_locale is NOT NULL in
	// 0001_init.sql, so a NULL on it is unrepresentable — the DB rejects it —
	// which is why it is not scanned through *string.)
	pgxMin, err := pgxRepo.Workspace(ctx, minimal.ID)
	if err != nil {
		t.Fatalf("pgx Workspace(minimal): %v", err)
	}
	gormMin, err := gormRepo.Workspace(ctx, minimal.ID)
	if err != nil {
		t.Fatalf("gorm Workspace(minimal): %v", err)
	}
	if pgxMin != gormMin {
		t.Fatalf("Workspace(minimal) mismatch:\n pgx=%+v\ngorm=%+v", pgxMin, gormMin)
	}
	if pgxMin.DataResidency != "" || pgxMin.SSOConnectionID != "" || pgxMin.DefaultLocale != "en" {
		t.Fatalf("minimal workspace field mapping wrong: %+v", pgxMin)
	}

	// WorkspaceIDs: identical set, both ordered by id.
	pgxIDs, err := pgxRepo.WorkspaceIDs(ctx)
	if err != nil {
		t.Fatalf("pgx WorkspaceIDs: %v", err)
	}
	gormIDs, err := gormRepo.WorkspaceIDs(ctx)
	if err != nil {
		t.Fatalf("gorm WorkspaceIDs: %v", err)
	}
	if fmt.Sprint(pgxIDs) != fmt.Sprint(gormIDs) {
		t.Fatalf("WorkspaceIDs differ: pgx=%v gorm=%v", pgxIDs, gormIDs)
	}
	if len(pgxIDs) != 2 {
		t.Fatalf("expected 2 workspace ids, got %d", len(pgxIDs))
	}

	// Soft-delete scoping: GORM soft-delete hides the row from BOTH backends.
	if err := gdb.Delete(&models.Workspace{}, "id = ?", minimal.ID).Error; err != nil {
		t.Fatalf("soft-delete: %v", err)
	}
	if _, err := pgxRepo.WorkspaceIDByTenant(ctx, "tenant-beta"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("pgx should not see soft-deleted workspace: %v", err)
	}
	if _, err := pgxRepo.Workspace(ctx, minimal.ID); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("pgx Workspace should not see soft-deleted row: %v", err)
	}
	pgxIDs, err = pgxRepo.WorkspaceIDs(ctx)
	if err != nil {
		t.Fatalf("pgx WorkspaceIDs after delete: %v", err)
	}
	if len(pgxIDs) != 1 || pgxIDs[0] != full.ID {
		t.Fatalf("pgx WorkspaceIDs after soft-delete = %v, want [%s]", pgxIDs, full.ID)
	}
}

// auditRow is the read-back view of one chain row used to assert chain integrity.
type auditRow struct {
	ChainSeq  int64
	PrevHash  string
	ChainHash string
	Action    string
	TargetRef string
	Actor     string
	Metadata  *string // nil when the column is SQL NULL
}

// readChain returns the workspace's audit rows ordered by chain_seq.
func readChain(t *testing.T, ctx context.Context, pool *pgxpool.Pool, workspaceID uuid.UUID) []auditRow {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT chain_seq, prev_hash, chain_hash, action, target_ref, actor, metadata::text
		   FROM audit_events WHERE workspace_id = $1 ORDER BY chain_seq`, workspaceID)
	if err != nil {
		t.Fatalf("read chain: %v", err)
	}
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var r auditRow
		if err := rows.Scan(&r.ChainSeq, &r.PrevHash, &r.ChainHash, &r.Action, &r.TargetRef, &r.Actor, &r.Metadata); err != nil {
			t.Fatalf("scan chain row: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate chain: %v", err)
	}
	return out
}

// assertChainIntact verifies chain_seq is 1..N contiguous and each row's
// prev_hash equals the previous row's chain_hash (the first is empty).
func assertChainIntact(t *testing.T, chain []auditRow) {
	t.Helper()
	for i, r := range chain {
		wantSeq := int64(i + 1)
		if r.ChainSeq != wantSeq {
			t.Fatalf("row %d: chain_seq=%d want %d", i, r.ChainSeq, wantSeq)
		}
		wantPrev := ""
		if i > 0 {
			wantPrev = chain[i-1].ChainHash
		}
		if r.PrevHash != wantPrev {
			t.Fatalf("row %d: prev_hash=%q want %q (chain forked)", i, r.PrevHash, wantPrev)
		}
	}
}

// TestPgxAuditChainInteropWithGorm proves an event appended through the pgx
// adapter and one appended through the GORM lifecycle appender link into the
// SAME hash chain: the chain stays intact when the two backends interleave, and
// the recorded hashes match an independent recomputation via auditchain.Hash.
func TestPgxAuditChainInteropWithGorm(t *testing.T) {
	ctx, gdb, pool := pgxTestSetup(t)
	pgxRepo := database.NewPgxAuditRepo(pool)
	ws := seedWorkspace(t, gdb, &models.Workspace{Name: "acme", IAMCoreTenantID: "tenant-" + uuid.NewString()})

	clock := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)

	// Event 1 via pgx, event 2 via GORM, event 3 via pgx — interleaving the two
	// backends on one chain.
	if err := pgxRepo.AppendAudit(ctx, clock, database.AuditInput{
		WorkspaceID: ws.ID, Actor: "a1", Action: "target.create", TargetRef: "t1", Metadata: []byte(`{"k":"v1"}`),
	}); err != nil {
		t.Fatalf("pgx append 1: %v", err)
	}
	if err := lifecycle.AppendAudit(ctx, gdb, clock, lifecycle.AuditInput{
		WorkspaceID: ws.ID, Actor: "a2", Action: "target.update", TargetRef: "t2", Metadata: []byte(`{"k":"v2"}`),
	}); err != nil {
		t.Fatalf("gorm append 2: %v", err)
	}
	if err := pgxRepo.AppendAudit(ctx, clock, database.AuditInput{
		WorkspaceID: ws.ID, Actor: "a3", Action: "token.mint", TargetRef: "t3", // nil metadata → NULL
	}); err != nil {
		t.Fatalf("pgx append 3: %v", err)
	}

	chain := readChain(t, ctx, pool, ws.ID)
	if len(chain) != 3 {
		t.Fatalf("expected 3 chain rows, got %d", len(chain))
	}
	assertChainIntact(t, chain)

	// Independently recompute each chain hash and confirm the stored value
	// matches — proving both backends use the identical hashing contract.
	inputs := []struct {
		action, target string
		meta           []byte
	}{
		{"target.create", "t1", []byte(`{"k":"v1"}`)},
		{"target.update", "t2", []byte(`{"k":"v2"}`)},
		{"token.mint", "t3", nil},
	}
	prev := ""
	for i, in := range inputs {
		want := auditchain.Hash(prev, ws.ID, in.action, in.target, in.meta, clock)
		if chain[i].ChainHash != want {
			t.Fatalf("row %d chain_hash=%s want %s", i, chain[i].ChainHash, want)
		}
		prev = chain[i].ChainHash
	}

	// Metadata storage parity: non-empty stored as jsonb, empty stored as NULL.
	if chain[0].Metadata == nil {
		t.Fatalf("row 0 metadata should be stored, got NULL")
	}
	if chain[2].Metadata != nil {
		t.Fatalf("row 2 (nil metadata) should be SQL NULL, got %q", *chain[2].Metadata)
	}
}

// TestPgxAuditConcurrentNoFork fires many concurrent pgx appends at one
// workspace and proves the per-workspace advisory lock serialises them so the
// chain never forks: chain_seq is 1..N with no gaps or duplicates and every
// prev_hash links to the prior chain_hash.
func TestPgxAuditConcurrentNoFork(t *testing.T) {
	ctx, gdb, pool := pgxTestSetup(t)
	pgxRepo := database.NewPgxAuditRepo(pool)
	ws := seedWorkspace(t, gdb, &models.Workspace{Name: "acme", IAMCoreTenantID: "tenant-" + uuid.NewString()})

	const n = 25
	clock := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- pgxRepo.AppendAudit(ctx, clock, database.AuditInput{
				WorkspaceID: ws.ID,
				Actor:       fmt.Sprintf("actor-%d", i),
				Action:      "concurrent.append",
				TargetRef:   fmt.Sprintf("ref-%d", i),
				Metadata:    []byte(fmt.Sprintf(`{"i":%d}`, i)),
			})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent append: %v", err)
		}
	}

	chain := readChain(t, ctx, pool, ws.ID)
	if len(chain) != n {
		t.Fatalf("expected %d rows, got %d", n, len(chain))
	}
	assertChainIntact(t, chain)

	// chain_seq must be exactly the set 1..n (no duplicates, no gaps).
	seqs := make([]int64, len(chain))
	for i, r := range chain {
		seqs[i] = r.ChainSeq
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	for i, s := range seqs {
		if s != int64(i+1) {
			t.Fatalf("chain_seq set has a gap/duplicate at index %d: %v", i, seqs)
		}
	}
}
