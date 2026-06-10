//go:build integration

package pam

import (
	"context"
	"encoding/base64"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/migrations"
	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// TestLeaseLifecyclePostgres runs the full JIT lease state machine against a
// real Postgres so the production migration (0016_pam_leases), the FOR UPDATE row lock in
// loadForUpdate, the partial-index-backed expiry sweep, and the audit-chain
// append are all exercised on the actual engine — none of which SQLite (the
// hermetic unit-test backend) can model. It skips unless ACCESS_TEST_DATABASE_URL
// is set, matching the migration + promote integration tests' convention.
//
// The database it points at is treated as throwaway: the schema is reset and
// the production migrations re-applied (not GORM AutoMigrate, which cannot
// reconcile the migration-managed constraint names).
func TestLeaseLifecyclePostgres(t *testing.T) {
	dsn := os.Getenv("ACCESS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("ACCESS_TEST_DATABASE_URL not set; skipping Postgres lease lifecycle integration test")
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

	// Seed a workspace + target.
	ws := &models.Workspace{Name: "tenant-lease-" + uuid.NewString(), IAMCoreTenantID: uuid.NewString(), Plan: "base"}
	if err := db.Create(ws).Error; err != nil {
		t.Fatalf("seed workspace: %v", err)
	}
	enc, err := access.CredentialEncryptorFromKey(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatalf("encryptor: %v", err)
	}
	v := NewVault(db, enc, nil)
	target, err := v.CreateTarget(ctx, CreateTargetInput{
		WorkspaceID: ws.ID, Name: "box", Protocol: models.PAMProtocolSSH,
		Address: "host:22", Username: "root", Secret: Secret{Password: "pw"}, Actor: "admin",
	})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	cur := now
	clock := func() time.Time { return cur }
	leases := NewPAMLeaseService(db, nil)
	leases.SetClock(clock)
	broker := NewBroker(db, v, nil)
	broker.SetClock(clock)
	broker.SetLeaseValidator(leases)

	// Request → Approve.
	lease, err := leases.RequestLease(ctx, RequestLeaseInput{
		WorkspaceID: ws.ID, TargetID: target.ID, Subject: "alice", RequestedBy: "alice", TTL: time.Minute, Reason: "deploy",
	})
	if err != nil {
		t.Fatalf("RequestLease: %v", err)
	}
	if lease.State != models.PAMLeaseStateRequested {
		t.Fatalf("want requested, got %q", lease.State)
	}
	if _, err := leases.ApproveLease(ctx, ws.ID, lease.ID, "carol", time.Minute); err != nil {
		t.Fatalf("ApproveLease: %v", err)
	}

	// First lease-bound redemption flips approved → active.
	raw, _, err := broker.MintConnectToken(ctx, MintInput{
		WorkspaceID: ws.ID, TargetID: target.ID, Subject: "alice", Actor: "alice", LeaseID: &lease.ID,
	})
	if err != nil {
		t.Fatalf("MintConnectToken: %v", err)
	}
	if _, err := broker.RedeemConnectToken(ctx, raw, "1.2.3.4"); err != nil {
		t.Fatalf("RedeemConnectToken: %v", err)
	}
	active, err := leases.GetLease(ctx, ws.ID, lease.ID)
	if err != nil {
		t.Fatalf("GetLease: %v", err)
	}
	if active.State != models.PAMLeaseStateActive {
		t.Fatalf("want active, got %q", active.State)
	}

	// Advance past TTL and sweep: the partial-index expiry sweep claims the
	// lease exactly once and audits it.
	cur = now.Add(2 * time.Minute)
	n, err := leases.ExpireLeases(ctx, ws.ID)
	if err != nil || n != 1 {
		t.Fatalf("ExpireLeases: n=%d err=%v (want 1, nil)", n, err)
	}
	if n, err := leases.ExpireLeases(ctx, ws.ID); err != nil || n != 0 {
		t.Fatalf("idempotent ExpireLeases: n=%d err=%v (want 0, nil)", n, err)
	}
	expired, err := leases.GetLease(ctx, ws.ID, lease.ID)
	if err != nil {
		t.Fatalf("GetLease: %v", err)
	}
	if expired.State != models.PAMLeaseStateExpired {
		t.Fatalf("want expired, got %q", expired.State)
	}

	// A token minted after expiry must fail closed against the dead lease.
	if _, _, err := broker.MintConnectToken(ctx, MintInput{
		WorkspaceID: ws.ID, TargetID: target.ID, Subject: "alice", Actor: "alice", LeaseID: &lease.ID,
	}); err == nil {
		t.Fatal("mint against expired lease should fail closed")
	}

	// Audit chain holds request, approve, and exactly one expiry event.
	for action, want := range map[string]int64{
		"pam.lease.requested": 1,
		"pam.lease.approved":  1,
		"pam.lease.expired":   1,
	} {
		var c int64
		db.Model(&models.AuditEvent{}).Where("workspace_id = ? AND action = ? AND target_ref = ?", ws.ID, action, lease.ID.String()).Count(&c)
		if c != want {
			t.Fatalf("audit %q: got %d, want %d", action, c, want)
		}
	}
}
