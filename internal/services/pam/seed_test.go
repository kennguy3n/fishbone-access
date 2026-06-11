package pam

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// TestRecordRecordingAppendsEvidence proves a recording reference lands in the
// audit chain as a pam.session.recording event carrying the replay key + hash,
// and that the no-op / validation guards behave.
func TestRecordRecordingAppendsEvidence(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	ctx := context.Background()
	mgr := NewSessionManager(db, nil, nil)

	target := uuid.New()
	session := &models.PAMSession{
		WorkspaceID: ws,
		TargetID:    target,
		Subject:     "alice",
		Protocol:    models.PAMProtocolSSH,
		State:       models.PAMSessionActive,
	}
	session.ID = uuid.New()

	ref := RecordingRef{
		Key:       "sessions/" + session.ID.String() + "/replay.bin",
		SHA256:    "abc123",
		Bytes:     256,
		Truncated: false,
	}
	if err := mgr.RecordRecording(ctx, session, ref); err != nil {
		t.Fatalf("RecordRecording: %v", err)
	}

	var rows []models.AuditEvent
	if err := db.Where("workspace_id = ? AND action = ?", ws, "pam.session.recording").Find(&rows).Error; err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 pam.session.recording row, got %d", len(rows))
	}
	if rows[0].TargetRef != target.String() {
		t.Errorf("target_ref = %q, want %q", rows[0].TargetRef, target.String())
	}
	var md map[string]any
	if err := json.Unmarshal(rows[0].Metadata, &md); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if md["replay_key"] != ref.Key || md["sha256"] != ref.SHA256 {
		t.Fatalf("recording metadata missing reference: %v", md)
	}

	// Empty ref key is a no-op (recording disabled / store failed): no new row.
	if err := mgr.RecordRecording(ctx, session, RecordingRef{}); err != nil {
		t.Fatalf("RecordRecording empty ref: %v", err)
	}
	var after int64
	db.Model(&models.AuditEvent{}).Where("workspace_id = ? AND action = ?", ws, "pam.session.recording").Count(&after)
	if after != 1 {
		t.Fatalf("empty ref must not append; want 1 row, got %d", after)
	}

	// Nil session is a validation error.
	if err := mgr.RecordRecording(ctx, nil, ref); err == nil {
		t.Fatalf("expected error for nil session")
	}
}

// TestFindTargetByName proves the exact, workspace-scoped name lookup the
// seeder relies on for idempotency: it resolves an existing target by name and
// reports ErrTargetNotFound for an absent one. Because it is an indexed lookup
// rather than a scan of a capped ListTargets page, the seeder converges on a
// single target regardless of how large the workspace's target catalog grows.
func TestFindTargetByName(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	ctx := context.Background()
	vault := NewVault(db, newTestEncryptor(t), nil)

	created, err := vault.CreateTarget(ctx, CreateTargetInput{
		WorkspaceID: ws,
		Name:        "prod-db",
		Protocol:    models.PAMProtocolSSH,
		Address:     "db.internal:22",
		Secret:      Secret{Password: "pw"},
		Actor:       "admin",
	})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}

	got, err := vault.FindTargetByName(ctx, ws, "prod-db")
	if err != nil {
		t.Fatalf("FindTargetByName: %v", err)
	}
	if got.ID != created.ID {
		t.Fatalf("FindTargetByName returned %s, want %s", got.ID, created.ID)
	}

	// Surrounding whitespace is normalised to match CreateTarget's trim.
	if _, err := vault.FindTargetByName(ctx, ws, "  prod-db  "); err != nil {
		t.Fatalf("FindTargetByName trimmed: %v", err)
	}

	// An absent name is the not-found sentinel, not a hard error, so callers can
	// branch to "create".
	if _, err := vault.FindTargetByName(ctx, ws, "missing"); !errors.Is(err, ErrTargetNotFound) {
		t.Fatalf("absent name: got %v, want ErrTargetNotFound", err)
	}
}

// TestSeederSeedsPrivilegedSession runs the scenario seeder end-to-end through
// the real broker/session manager and asserts the full privileged-access
// evidence trail (opened → command → recording → closed) lands in the chain,
// and that re-running with the same target name is idempotent.
func TestSeederSeedsPrivilegedSession(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	ctx := context.Background()

	vault := NewVault(db, newTestEncryptor(t), nil)
	broker := NewBroker(db, vault, nil)
	mgr := NewSessionManager(db, nil, nil)
	seeder := NewSeeder(vault, broker, mgr)

	in := SeedPrivilegedSessionInput{
		WorkspaceID: ws,
		Subject:     "alice",
		Actor:       "admin",
		TargetName:  "prod-db",
		Protocol:    models.PAMProtocolSSH,
		Address:     "db.internal:22",
		Secret:      Secret{Password: "pw"},
		Commands:    []string{"select 1;", "select 2;"},
		Recording: RecordingRef{
			Key:    "sessions/seed/replay.bin",
			SHA256: "feedface",
			Bytes:  512,
		},
	}
	res, err := seeder.SeedPrivilegedSession(ctx, in)
	if err != nil {
		t.Fatalf("SeedPrivilegedSession: %v", err)
	}
	if res.Commands != 2 || !res.Recorded {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.Session == nil || res.Session.State != models.PAMSessionActive {
		// The returned session snapshot is the freshly-opened one; the DB row is
		// closed below. We only assert it was populated.
		t.Fatalf("expected a populated opened session, got %+v", res.Session)
	}

	// The chain must carry the full lifecycle for this workspace.
	for action, want := range map[string]int64{
		"pam.session.opened":    1,
		"pam.command":           2,
		"pam.session.recording": 1,
		"pam.session.closed":    1,
	} {
		var n int64
		db.Model(&models.AuditEvent{}).Where("workspace_id = ? AND action = ?", ws, action).Count(&n)
		if n != want {
			t.Errorf("action %q: got %d audit rows, want %d", action, n, want)
		}
	}

	// The seeded session row is closed (not left dangling Active).
	var closed int64
	db.Model(&models.PAMSession{}).Where("workspace_id = ? AND state = ?", ws, models.PAMSessionClosed).Count(&closed)
	if closed != 1 {
		t.Fatalf("want 1 closed session row, got %d", closed)
	}

	// The target-creation event is attributed to the scenario's actor, not left
	// blank — the seeder resolves the actor before creating the target.
	var created models.AuditEvent
	if err := db.Where("workspace_id = ? AND action = ?", ws, "pam.target.created").Take(&created).Error; err != nil {
		t.Fatalf("query pam.target.created: %v", err)
	}
	if created.Actor != "admin" {
		t.Errorf("pam.target.created actor = %q, want %q", created.Actor, "admin")
	}

	// Idempotent target reuse: a second seed run must not create a duplicate target.
	if _, err := seeder.SeedPrivilegedSession(ctx, in); err != nil {
		t.Fatalf("second SeedPrivilegedSession: %v", err)
	}
	var targets int64
	db.Model(&models.PAMTarget{}).Where("workspace_id = ?", ws).Count(&targets)
	if targets != 1 {
		t.Fatalf("want 1 target after two seed runs (idempotent), got %d", targets)
	}
}
