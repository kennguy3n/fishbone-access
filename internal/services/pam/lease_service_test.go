package pam

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// seedTarget creates a PAM target through the vault so its sealed credential
// envelope is real (the lease/broker tests exercise the same path production
// uses).
func seedLeaseTarget(t *testing.T, v *Vault, ws uuid.UUID, name string) *models.PAMTarget {
	t.Helper()
	target, err := v.CreateTarget(context.Background(), CreateTargetInput{
		WorkspaceID: ws,
		Name:        name,
		Protocol:    models.PAMProtocolSSH,
		Address:     "host:22",
		Username:    "root",
		Secret:      Secret{Password: "pw"},
		Actor:       "admin",
	})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	return target
}

// fakeTerminator records the leases it was asked to tear down.
type fakeTerminator struct{ terminated []uuid.UUID }

func (f *fakeTerminator) TerminateLeaseSessions(_ context.Context, _ uuid.UUID, leaseID uuid.UUID, _ string) error {
	f.terminated = append(f.terminated, leaseID)
	return nil
}

// TestLeaseLifecycle walks the happy path Requested → Approved → Active and
// asserts the derived state at each step, plus that the credential broker
// activates the lease on first session open.
func TestLeaseLifecycle(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	v := NewVault(db, newTestEncryptor(t), nil)
	target := seedLeaseTarget(t, v, ws, "box")

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	leases := NewPAMLeaseService(db, nil) // nil ai → fail-open fallback
	leases.SetClock(clock)
	broker := NewBroker(db, v, nil)
	broker.SetClock(clock)
	broker.SetLeaseValidator(leases)

	// Request.
	lease, err := leases.RequestLease(context.Background(), RequestLeaseInput{
		WorkspaceID: ws, TargetID: target.ID, Subject: "alice", RequestedBy: "alice",
		TTL: time.Hour, Reason: "deploy hotfix",
	})
	if err != nil {
		t.Fatalf("RequestLease: %v", err)
	}
	if lease.State != models.PAMLeaseStateRequested {
		t.Fatalf("want requested, got %q", lease.State)
	}
	// Risk is persisted even on the fail-open fallback path.
	if lease.RiskLevel == "" {
		t.Fatal("risk level not persisted")
	}

	// Approve.
	approved, err := leases.ApproveLease(context.Background(), ws, lease.ID, "carol", 0)
	if err != nil {
		t.Fatalf("ApproveLease: %v", err)
	}
	if approved.State != models.PAMLeaseStateApproved {
		t.Fatalf("want approved, got %q", approved.State)
	}
	if approved.GrantedAt == nil || approved.ExpiresAt == nil {
		t.Fatal("approve must stamp granted_at and expires_at")
	}
	if got := approved.ExpiresAt.Sub(*approved.GrantedAt); got != time.Hour {
		t.Fatalf("window measured from approval should be 1h, got %s", got)
	}

	// Mint + redeem a lease-bound token: first open flips approved → active.
	raw, _, err := broker.MintConnectToken(context.Background(), MintInput{
		WorkspaceID: ws, TargetID: target.ID, Subject: "alice", Actor: "alice", LeaseID: &lease.ID,
	})
	if err != nil {
		t.Fatalf("MintConnectToken: %v", err)
	}
	if _, err := broker.RedeemConnectToken(context.Background(), raw, "1.2.3.4"); err != nil {
		t.Fatalf("RedeemConnectToken: %v", err)
	}

	active, err := leases.GetLease(context.Background(), ws, lease.ID)
	if err != nil {
		t.Fatalf("GetLease: %v", err)
	}
	if active.State != models.PAMLeaseStateActive {
		t.Fatalf("want active after first redeem, got %q", active.State)
	}
	if active.ActivatedAt == nil {
		t.Fatal("activated_at must be stamped on first session open")
	}
}

// TestApproveTerminalRejected confirms illegal transitions out of the terminal
// states are rejected with ErrLeaseTerminal.
func TestApproveTerminalRejected(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	v := NewVault(db, newTestEncryptor(t), nil)
	target := seedLeaseTarget(t, v, ws, "box")
	leases := NewPAMLeaseService(db, nil)

	// Revoked lease cannot be approved.
	l1, err := leases.RequestLease(context.Background(), RequestLeaseInput{
		WorkspaceID: ws, TargetID: target.ID, Subject: "alice", RequestedBy: "alice", TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("RequestLease: %v", err)
	}
	if _, err := leases.RevokeLease(context.Background(), ws, l1.ID, "admin", "denied"); err != nil {
		t.Fatalf("RevokeLease: %v", err)
	}
	if _, err := leases.ApproveLease(context.Background(), ws, l1.ID, "carol", 0); !errors.Is(err, ErrLeaseTerminal) {
		t.Fatalf("approve of revoked lease: want ErrLeaseTerminal, got %v", err)
	}

	// A lease revoked after approval is terminal and cannot be re-approved.
	// (An approved lease whose TTL merely lapsed is NOT re-approvable either,
	// but that path is the idempotent no-op — re-approval never extends a
	// window — so the terminal guard is exercised via revoke, the only way to
	// reach a terminal state that is not already granted-and-live.)
	l2, err := leases.RequestLease(context.Background(), RequestLeaseInput{
		WorkspaceID: ws, TargetID: target.ID, Subject: "bob", RequestedBy: "bob", TTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("RequestLease: %v", err)
	}
	if _, err := leases.ApproveLease(context.Background(), ws, l2.ID, "carol", time.Minute); err != nil {
		t.Fatalf("ApproveLease: %v", err)
	}
	if _, err := leases.RevokeLease(context.Background(), ws, l2.ID, "admin", "kill"); err != nil {
		t.Fatalf("RevokeLease: %v", err)
	}
	if _, err := leases.ApproveLease(context.Background(), ws, l2.ID, "carol", 0); !errors.Is(err, ErrLeaseTerminal) {
		t.Fatalf("approve of revoked-after-approval lease: want ErrLeaseTerminal, got %v", err)
	}
}

// TestExpireLeasesSweep verifies the TTL auto-expire sweep is idempotent and
// audits exactly once per lease.
func TestExpireLeasesSweep(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	v := NewVault(db, newTestEncryptor(t), nil)
	target := seedLeaseTarget(t, v, ws, "box")

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	cur := now
	leases := NewPAMLeaseService(db, nil)
	leases.SetClock(func() time.Time { return cur })

	lease, err := leases.RequestLease(context.Background(), RequestLeaseInput{
		WorkspaceID: ws, TargetID: target.ID, Subject: "alice", RequestedBy: "alice", TTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("RequestLease: %v", err)
	}
	if _, err := leases.ApproveLease(context.Background(), ws, lease.ID, "carol", time.Minute); err != nil {
		t.Fatalf("ApproveLease: %v", err)
	}

	// Before TTL: nothing to sweep.
	if n, err := leases.ExpireLeases(context.Background(), ws); err != nil || n != 0 {
		t.Fatalf("pre-TTL sweep: n=%d err=%v (want 0, nil)", n, err)
	}

	cur = now.Add(2 * time.Minute)
	n, err := leases.ExpireLeases(context.Background(), ws)
	if err != nil || n != 1 {
		t.Fatalf("sweep: n=%d err=%v (want 1, nil)", n, err)
	}
	// Idempotent: re-running does not double-expire.
	if n, err := leases.ExpireLeases(context.Background(), ws); err != nil || n != 0 {
		t.Fatalf("re-sweep: n=%d err=%v (want 0, nil)", n, err)
	}

	got, err := leases.GetLease(context.Background(), ws, lease.ID)
	if err != nil {
		t.Fatalf("GetLease: %v", err)
	}
	if got.State != models.PAMLeaseStateExpired {
		t.Fatalf("want expired, got %q", got.State)
	}

	// Exactly one expiry audit event.
	var auditCount int64
	db.Model(&models.AuditEvent{}).Where("workspace_id = ? AND action = ?", ws, "pam.lease.expired").Count(&auditCount)
	if auditCount != 1 {
		t.Fatalf("want 1 expiry audit, got %d", auditCount)
	}
}

// TestLeaseBoundSecretActiveOnly proves the credential is brokered only while
// the lease is live: a token bound to a lease that is revoked or expired before
// redemption fails closed.
func TestLeaseBoundSecretActiveOnly(t *testing.T) {
	for _, tc := range []struct {
		name string
		kill func(leases *PAMLeaseService, ws, leaseID uuid.UUID, advance func())
	}{
		{"revoked", func(leases *PAMLeaseService, ws, leaseID uuid.UUID, _ func()) {
			if _, err := leases.RevokeLease(context.Background(), ws, leaseID, "admin", "kill"); err != nil {
				t.Fatalf("RevokeLease: %v", err)
			}
		}},
		{"expired", func(leases *PAMLeaseService, ws, leaseID uuid.UUID, advance func()) {
			advance()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newTestDB(t)
			ws := seedWorkspace(t, db, "tenant-a")
			v := NewVault(db, newTestEncryptor(t), nil)
			target := seedLeaseTarget(t, v, ws, "box")

			now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
			cur := now
			clock := func() time.Time { return cur }
			leases := NewPAMLeaseService(db, nil)
			leases.SetClock(clock)
			broker := NewBroker(db, v, nil)
			broker.SetClock(clock)
			broker.SetLeaseValidator(leases)

			lease, err := leases.RequestLease(context.Background(), RequestLeaseInput{
				WorkspaceID: ws, TargetID: target.ID, Subject: "alice", RequestedBy: "alice", TTL: time.Minute,
			})
			if err != nil {
				t.Fatalf("RequestLease: %v", err)
			}
			if _, err := leases.ApproveLease(context.Background(), ws, lease.ID, "carol", time.Minute); err != nil {
				t.Fatalf("ApproveLease: %v", err)
			}
			// Mint while live.
			raw, _, err := broker.MintConnectToken(context.Background(), MintInput{
				WorkspaceID: ws, TargetID: target.ID, Subject: "alice", Actor: "alice", LeaseID: &lease.ID,
			})
			if err != nil {
				t.Fatalf("MintConnectToken: %v", err)
			}
			// Kill the lease before redemption.
			tc.kill(leases, ws, lease.ID, func() { cur = now.Add(2 * time.Minute) })

			if _, err := broker.RedeemConnectToken(context.Background(), raw, "1.2.3.4"); !errors.Is(err, ErrConnectToken) {
				t.Fatalf("redeem against dead lease: want ErrConnectToken, got %v", err)
			}
		})
	}
}

// TestLeaseMintRejectedWhenLeaseDead confirms even minting a token requires a
// live lease (fail-closed at mint, not just redeem).
func TestLeaseMintRejectedWhenLeaseDead(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	v := NewVault(db, newTestEncryptor(t), nil)
	target := seedLeaseTarget(t, v, ws, "box")
	leases := NewPAMLeaseService(db, nil)
	broker := NewBroker(db, v, nil)
	broker.SetLeaseValidator(leases)

	// Requested-but-not-approved lease is not live → mint must fail.
	lease, err := leases.RequestLease(context.Background(), RequestLeaseInput{
		WorkspaceID: ws, TargetID: target.ID, Subject: "alice", RequestedBy: "alice", TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("RequestLease: %v", err)
	}
	if _, _, err := broker.MintConnectToken(context.Background(), MintInput{
		WorkspaceID: ws, TargetID: target.ID, Subject: "alice", Actor: "alice", LeaseID: &lease.ID,
	}); !errors.Is(err, ErrLeaseNotApproved) {
		t.Fatalf("mint against unapproved lease: want ErrLeaseNotApproved, got %v", err)
	}
}

// TestLeaseCrossTenantIsolation proves a lease cannot be read or mutated from
// another workspace — the service returns the coarse not-found error so the
// other tenant cannot even probe existence.
func TestLeaseCrossTenantIsolation(t *testing.T) {
	db := newTestDB(t)
	wsA := seedWorkspace(t, db, "tenant-a")
	wsB := seedWorkspace(t, db, "tenant-b")
	v := NewVault(db, newTestEncryptor(t), nil)
	target := seedLeaseTarget(t, v, wsA, "box")
	leases := NewPAMLeaseService(db, nil)

	lease, err := leases.RequestLease(context.Background(), RequestLeaseInput{
		WorkspaceID: wsA, TargetID: target.ID, Subject: "alice", RequestedBy: "alice", TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("RequestLease: %v", err)
	}

	if _, err := leases.GetLease(context.Background(), wsB, lease.ID); !errors.Is(err, ErrLeaseNotFound) {
		t.Fatalf("cross-tenant GetLease: want ErrLeaseNotFound, got %v", err)
	}
	if _, err := leases.ApproveLease(context.Background(), wsB, lease.ID, "carol", 0); !errors.Is(err, ErrLeaseNotFound) {
		t.Fatalf("cross-tenant ApproveLease: want ErrLeaseNotFound, got %v", err)
	}
	if _, err := leases.RevokeLease(context.Background(), wsB, lease.ID, "carol", "x"); !errors.Is(err, ErrLeaseNotFound) {
		t.Fatalf("cross-tenant RevokeLease: want ErrLeaseNotFound, got %v", err)
	}
	// wsB's sweep must not touch wsA's lease.
	if n, _ := leases.ExpireLeases(context.Background(), wsB); n != 0 {
		t.Fatalf("cross-tenant sweep expired %d leases (want 0)", n)
	}
}

// TestLeaseAuditChain asserts each state transition appends the right audit
// action to the workspace hash chain.
func TestLeaseAuditChain(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	v := NewVault(db, newTestEncryptor(t), nil)
	target := seedLeaseTarget(t, v, ws, "box")
	leases := NewPAMLeaseService(db, nil)

	lease, err := leases.RequestLease(context.Background(), RequestLeaseInput{
		WorkspaceID: ws, TargetID: target.ID, Subject: "alice", RequestedBy: "alice", TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("RequestLease: %v", err)
	}
	if _, err := leases.ApproveLease(context.Background(), ws, lease.ID, "carol", 0); err != nil {
		t.Fatalf("ApproveLease: %v", err)
	}
	if _, err := leases.RevokeLease(context.Background(), ws, lease.ID, "admin", "done"); err != nil {
		t.Fatalf("RevokeLease: %v", err)
	}

	for _, action := range []string{"pam.lease.requested", "pam.lease.approved", "pam.lease.revoked"} {
		var c int64
		db.Model(&models.AuditEvent{}).Where("workspace_id = ? AND action = ? AND target_ref = ?", ws, action, lease.ID.String()).Count(&c)
		if c != 1 {
			t.Fatalf("want 1 %q audit for lease, got %d", action, c)
		}
	}
}

// TestRevokeTerminatesSessions checks the lease's session terminator runs when
// the lease leaves its live window, so the credential stops being brokered.
func TestRevokeTerminatesSessions(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	v := NewVault(db, newTestEncryptor(t), nil)
	target := seedLeaseTarget(t, v, ws, "box")
	leases := NewPAMLeaseService(db, nil)
	term := &fakeTerminator{}
	leases.SetSessionTerminator(term)

	lease, err := leases.RequestLease(context.Background(), RequestLeaseInput{
		WorkspaceID: ws, TargetID: target.ID, Subject: "alice", RequestedBy: "alice", TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("RequestLease: %v", err)
	}
	if _, err := leases.ApproveLease(context.Background(), ws, lease.ID, "carol", 0); err != nil {
		t.Fatalf("ApproveLease: %v", err)
	}
	if _, err := leases.RevokeLease(context.Background(), ws, lease.ID, "admin", "kill"); err != nil {
		t.Fatalf("RevokeLease: %v", err)
	}
	if len(term.terminated) != 1 || term.terminated[0] != lease.ID {
		t.Fatalf("revoke must terminate the lease's sessions, got %v", term.terminated)
	}

	// Idempotent revoke does not re-terminate.
	if _, err := leases.RevokeLease(context.Background(), ws, lease.ID, "admin", "kill"); err != nil {
		t.Fatalf("idempotent RevokeLease: %v", err)
	}
	if len(term.terminated) != 1 {
		t.Fatalf("second revoke should not re-terminate, got %v", term.terminated)
	}
}

// TestRequestLeaseRiskFailOpen confirms a nil AI client yields a degraded but
// persisted risk assessment rather than blocking the request.
func TestRequestLeaseRiskFailOpen(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	v := NewVault(db, newTestEncryptor(t), nil)
	target := seedLeaseTarget(t, v, ws, "box")
	leases := NewPAMLeaseService(db, nil) // no AI agent

	lease, err := leases.RequestLease(context.Background(), RequestLeaseInput{
		WorkspaceID: ws, TargetID: target.ID, Subject: "alice", RequestedBy: "alice", TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("RequestLease must not fail when AI is unavailable: %v", err)
	}
	if !lease.RiskDegraded {
		t.Fatal("risk should be marked degraded on fail-open fallback")
	}
	if lease.RiskLevel == "" {
		t.Fatal("a fallback risk level must still be persisted for audit")
	}
}
