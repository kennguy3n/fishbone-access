package recordings

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

func TestRetentionPolicyCRUDAndEffectiveDays(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	svc := NewService(db)

	// No override → falls back to the supplied default.
	if _, set, err := svc.GetRetentionPolicy(context.Background(), ws); err != nil || set {
		t.Fatalf("GetRetentionPolicy default: set=%v err=%v", set, err)
	}
	if days, err := svc.EffectiveRetentionDays(context.Background(), ws, 30); err != nil || days != 30 {
		t.Fatalf("effective default = %d err=%v, want 30", days, err)
	}

	// Override wins over the default.
	if _, err := svc.SetRetentionPolicy(context.Background(), ws, 7, "admin@acme.io"); err != nil {
		t.Fatalf("SetRetentionPolicy: %v", err)
	}
	p, set, err := svc.GetRetentionPolicy(context.Background(), ws)
	if err != nil || !set {
		t.Fatalf("GetRetentionPolicy after set: set=%v err=%v", set, err)
	}
	if p.RetentionDays != 7 || p.UpdatedBy != "admin@acme.io" {
		t.Errorf("policy = %+v, want 7 days by admin@acme.io", p)
	}
	if days, err := svc.EffectiveRetentionDays(context.Background(), ws, 30); err != nil || days != 7 {
		t.Fatalf("effective override = %d, want 7", days)
	}

	// Update in place (no duplicate row).
	if _, err := svc.SetRetentionPolicy(context.Background(), ws, 0, "admin@acme.io"); err != nil {
		t.Fatalf("update policy: %v", err)
	}
	var count int64
	db.Model(&models.RecordingRetentionPolicy{}).Where("workspace_id = ?", ws).Count(&count)
	if count != 1 {
		t.Errorf("policy rows = %d, want 1", count)
	}
	// 0 means retain indefinitely.
	if days, err := svc.EffectiveRetentionDays(context.Background(), ws, 30); err != nil || days != 0 {
		t.Fatalf("effective indefinite = %d, want 0", days)
	}

	if _, err := svc.SetRetentionPolicy(context.Background(), ws, -1, "x"); err == nil {
		t.Error("negative retention should be rejected")
	}
}

func TestPruneExpiredBlobsTiersAndPreservesAudit(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	target := seedTarget(t, db, ws, "db", "ssh")

	// One old (expired) and one recent recording.
	oldStart := time.Now().Add(-40 * 24 * time.Hour).UTC()
	oldEnd := oldStart.Add(time.Minute)
	oldSession := seedSession(t, db, ws, target, "a@acme.io", "ssh", models.PAMSessionClosed, oldStart, &oldEnd)
	recentStart := time.Now().Add(-1 * time.Hour).UTC()
	recentEnd := recentStart.Add(time.Minute)
	recentSession := seedSession(t, db, ws, target, "b@acme.io", "ssh", models.PAMSessionClosed, recentStart, &recentEnd)

	oldBlob, oldSHA := buildBlob(t, frame('I', oldStart, "ls\r"))
	recentBlob, recentSHA := buildBlob(t, frame('I', recentStart, "pwd\r"))
	seedRecordingAnchor(t, db, ws, oldSession, oldSHA, int64(len(oldBlob)), false)
	seedRecordingAnchor(t, db, ws, recentSession, recentSHA, int64(len(recentBlob)), false)

	store := newFakeStore()
	store.put(oldSession.String(), oldBlob)
	store.put(recentSession.String(), recentBlob)
	metrics := &fakeMetrics{}
	svc := NewService(db, WithReplayReader(store), WithReplayDeleter(store), WithMetrics(metrics))

	if _, err := svc.IndexClosedSessions(context.Background(), ws, 50); err != nil {
		t.Fatalf("index: %v", err)
	}

	// Count recording audit events before pruning (anchor only).
	beforeAnchors := countAudit(t, db, ws, recordingAuditAction)

	// 30-day retention → only the 40-day-old recording is expired.
	pruned, err := svc.PruneExpiredBlobs(context.Background(), ws, 30, 50)
	if err != nil {
		t.Fatalf("PruneExpiredBlobs: %v", err)
	}
	if pruned != 1 {
		t.Fatalf("pruned = %d, want 1", pruned)
	}
	if _, p, _ := metrics.snapshot(); p != 1 {
		t.Errorf("pruned metric = %d, want 1", p)
	}

	// Old blob deleted; recent blob retained.
	if store.has(oldSession.String()) {
		t.Error("old blob should be tiered out")
	}
	if !store.has(recentSession.String()) {
		t.Error("recent blob must be retained")
	}

	// Metadata row PRESERVED, flagged pruned.
	var oldRec models.SessionRecording
	if err := db.Where("session_id = ?", oldSession).First(&oldRec).Error; err != nil {
		t.Fatalf("old recording row must survive prune: %v", err)
	}
	if !oldRec.BlobPruned || oldRec.BlobPrunedAt == nil {
		t.Errorf("row not flagged pruned: %+v", oldRec)
	}

	// Audit integrity: the original anchor event is UNTOUCHED and a NEW prune
	// event was appended (chain grows, never rewrites).
	afterAnchors := countAudit(t, db, ws, recordingAuditAction)
	if afterAnchors != beforeAnchors {
		t.Errorf("anchor events changed: before=%d after=%d (must be preserved)", beforeAnchors, afterAnchors)
	}
	if got := countAudit(t, db, ws, recordingPrunedAuditAction); got != 1 {
		t.Errorf("prune audit events = %d, want 1", got)
	}

	// Idempotent: a second prune finds nothing new (blob already gone).
	pruned2, err := svc.PruneExpiredBlobs(context.Background(), ws, 30, 50)
	if err != nil {
		t.Fatalf("second prune: %v", err)
	}
	if pruned2 != 0 {
		t.Errorf("second prune = %d, want 0", pruned2)
	}
}

func TestPruneDisabledWhenIndefiniteOrNoDeleter(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	target := seedTarget(t, db, ws, "db", "ssh")
	oldStart := time.Now().Add(-100 * 24 * time.Hour).UTC()
	oldEnd := oldStart.Add(time.Minute)
	session := seedSession(t, db, ws, target, "a@acme.io", "ssh", models.PAMSessionClosed, oldStart, &oldEnd)
	blob, sha := buildBlob(t, frame('I', oldStart, "ls\r"))
	seedRecordingAnchor(t, db, ws, session, sha, int64(len(blob)), false)
	store := newFakeStore()
	store.put(session.String(), blob)

	// No deleter wired → never prunes (refuses to orphan storage).
	noDeleter := NewService(db, WithReplayReader(store))
	if _, err := noDeleter.IndexClosedSessions(context.Background(), ws, 10); err != nil {
		t.Fatalf("index: %v", err)
	}
	if n, err := noDeleter.PruneExpiredBlobs(context.Background(), ws, 30, 10); err != nil || n != 0 {
		t.Fatalf("prune without deleter = %d err=%v, want 0", n, err)
	}

	// Deleter wired but retention=0 (indefinite) → never prunes.
	withDeleter := NewService(db, WithReplayReader(store), WithReplayDeleter(store))
	if n, err := withDeleter.PruneExpiredBlobs(context.Background(), ws, 0, 10); err != nil || n != 0 {
		t.Fatalf("prune indefinite = %d err=%v, want 0", n, err)
	}
	if !store.has(session.String()) {
		t.Error("blob must remain when retention disabled")
	}
}

func countAudit(t *testing.T, db *gorm.DB, ws uuid.UUID, action string) int64 {
	t.Helper()
	var n int64
	if err := db.Model(&models.AuditEvent{}).
		Where("workspace_id = ? AND action = ?", ws, action).
		Count(&n).Error; err != nil {
		t.Fatalf("count audit: %v", err)
	}
	return n
}
