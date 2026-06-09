//go:build integration

package compliance

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/migrations"
	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
)

// TestEvidenceStreamChainPostgres exercises the evidence stream against a real
// Postgres, which (unlike SQLite) stores timestamptz at microsecond precision.
// This is the dialect where a naive chain that hashed Go's nanosecond clock but
// persisted a truncated created_at would fail to recompute; the test is the
// regression guard for the micro-truncation done in lifecycle.appendAudit.
//
// Skips unless ACCESS_TEST_DATABASE_URL points at a throwaway database (same
// gate the lifecycle Postgres integration tests use).
func TestEvidenceStreamChainPostgres(t *testing.T) {
	dsn := os.Getenv("ACCESS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("ACCESS_TEST_DATABASE_URL not set; skipping Postgres evidence-stream integration test")
	}
	ctx := context.Background()
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql db handle: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	if _, err := sqlDB.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	if _, err := migrations.Run(ctx, sqlDB); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	ws := &models.Workspace{Name: "tenant-evi", IAMCoreTenantID: "tenant-evi-" + uuid.NewString(), Plan: "base"}
	if err := db.Create(ws).Error; err != nil {
		t.Fatalf("seed workspace: %v", err)
	}

	// Append a spread of control-relevant events on the real chain. Spacing the
	// wall clock by sub-microsecond amounts would be erased by truncation; we
	// rely on chain_seq for ordering regardless.
	actions := []string{
		"policy.created",
		"policy.promoted",
		"access_grant.created",
		"certification.campaign.started",
		"access_grant.revoked",
		"compliance.export",
	}
	for _, a := range actions {
		if err := lifecycle.AppendAudit(ctx, db, time.Now(), lifecycle.AuditInput{
			WorkspaceID: ws.ID,
			Actor:       "auditor",
			Action:      a,
			TargetRef:   "t",
		}); err != nil {
			t.Fatalf("append %s: %v", a, err)
		}
	}

	svc := NewEvidenceService(db)

	// The whole point: a chain written with micro-truncated timestamps must
	// recompute cleanly on Postgres.
	v, err := svc.VerifyChain(ctx, ws.ID)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !v.OK || v.Status != chainStatusValid || v.Length != len(actions) {
		t.Fatalf("expected valid chain of %d on postgres, got %+v", len(actions), v)
	}

	// Stream + classification survive the round trip through timestamptz.
	recs, err := svc.Stream(ctx, ws.ID, EvidenceFilter{})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if len(recs) != len(actions) {
		t.Fatalf("expected %d records, got %d", len(actions), len(recs))
	}
	if recs[0].Kind != KindPolicyCreated || recs[len(recs)-1].Kind != KindEvidenceExported {
		t.Fatalf("classification/order wrong across postgres: %s..%s", recs[0].Kind, recs[len(recs)-1].Kind)
	}

	// Coverage computes against the real catalog.
	cov, err := svc.Coverage(ctx, ws.ID, FrameworkSOC2, nil, nil)
	if err != nil {
		t.Fatalf("Coverage: %v", err)
	}
	if cov.ControlsCovered == 0 {
		t.Fatalf("expected some covered controls on postgres")
	}

	// Tamper detection works on Postgres too: mutate a hashed column (action)
	// without recomputing the stored chain hash. Only the recompute check can
	// catch this — the row still links by prev_hash.
	if err := db.Model(&models.AuditEvent{}).
		Where("workspace_id = ? AND chain_seq = ?", ws.ID, int64(2)).
		Update("action", "policy.archived").Error; err != nil {
		t.Fatalf("tamper: %v", err)
	}
	v2, err := svc.VerifyChain(ctx, ws.ID)
	if err != nil {
		t.Fatalf("VerifyChain after tamper: %v", err)
	}
	if v2.OK || v2.Status != chainStatusTampered || v2.BrokenAtSeq != 2 {
		t.Fatalf("expected tampered at seq 2 on postgres, got %+v", v2)
	}
}
