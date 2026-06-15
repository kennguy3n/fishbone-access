package recordings

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// staticLister returns a fixed workspace set.
type staticLister struct{ ids []uuid.UUID }

func (l staticLister) WorkspaceIDs(context.Context) ([]uuid.UUID, error) { return l.ids, nil }

// gateFunc adapts a func to the HibernationGate interface.
type gateFunc func(uuid.UUID) (bool, error)

func (g gateFunc) ShouldRunPeriodic(_ context.Context, ws uuid.UUID) (bool, error) { return g(ws) }

func TestSweeperIndexesThenPrunes(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	target := seedTarget(t, db, ws, "db", "ssh")
	oldStart := time.Now().Add(-60 * 24 * time.Hour).UTC()
	oldEnd := oldStart.Add(time.Minute)
	session := seedSession(t, db, ws, target, "a@acme.io", "ssh", models.PAMSessionClosed, oldStart, &oldEnd)
	blob, sha := buildBlob(t, frame('I', oldStart, "ls\r"))
	seedRecordingAnchor(t, db, ws, session, sha, int64(len(blob)), false)
	store := newFakeStore()
	store.put(session.String(), blob)

	metrics := &fakeMetrics{}
	svc := NewService(db, WithReplayReader(store), WithReplayDeleter(store), WithMetrics(metrics))
	sweeper, err := NewSweeper(svc, staticLister{ids: []uuid.UUID{ws}}, SweepConfig{
		Interval:             time.Hour,
		DefaultRetentionDays: 30,
	})
	if err != nil {
		t.Fatalf("NewSweeper: %v", err)
	}

	// Run a single round directly (no ticker).
	sweeper.runOnce(context.Background())

	// Session was indexed AND its expired blob tiered out in the same round.
	var rec models.SessionRecording
	if err := db.Where("session_id = ?", session).First(&rec).Error; err != nil {
		t.Fatalf("session must be indexed: %v", err)
	}
	if !rec.BlobPruned {
		t.Error("expired blob should be pruned by the sweep")
	}
	idx, pr, _ := metrics.snapshot()
	if idx != 1 || pr != 1 {
		t.Errorf("metrics indexed=%d pruned=%d, want 1/1", idx, pr)
	}
}

func TestSweeperHibernationGateSkipsDormant(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	dormant := seedWorkspace(t, db, "dormant")
	target := seedTarget(t, db, dormant, "db", "ssh")
	start := time.Now().Add(-time.Hour).UTC()
	end := start.Add(time.Minute)
	session := seedSession(t, db, dormant, target, "a@acme.io", "ssh", models.PAMSessionClosed, start, &end)
	seedCommand(t, db, dormant, session, 1, "ls", models.PAMDecisionAllow, "")

	svc := NewService(db)
	sweeper, err := NewSweeper(svc, staticLister{ids: []uuid.UUID{dormant}}, SweepConfig{})
	if err != nil {
		t.Fatalf("NewSweeper: %v", err)
	}
	skips := 0
	sweeper.WithHibernationGate(gateFunc(func(uuid.UUID) (bool, error) { return false, nil }), func() { skips++ })

	sweeper.runOnce(context.Background())

	var count int64
	db.Model(&models.SessionRecording{}).Where("session_id = ?", session).Count(&count)
	if count != 0 {
		t.Error("dormant workspace should be skipped (no indexing)")
	}
	if skips != 1 {
		t.Errorf("skip callback fired %d times, want 1", skips)
	}
}

func TestSweeperGateFailOpen(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	target := seedTarget(t, db, ws, "db", "ssh")
	start := time.Now().Add(-time.Hour).UTC()
	end := start.Add(time.Minute)
	session := seedSession(t, db, ws, target, "a@acme.io", "ssh", models.PAMSessionClosed, start, &end)
	seedCommand(t, db, ws, session, 1, "ls", models.PAMDecisionAllow, "")

	svc := NewService(db)
	sweeper, err := NewSweeper(svc, staticLister{ids: []uuid.UUID{ws}}, SweepConfig{})
	if err != nil {
		t.Fatalf("NewSweeper: %v", err)
	}
	// Gate errors → fail-open → the workspace is STILL swept.
	sweeper.WithHibernationGate(gateFunc(func(uuid.UUID) (bool, error) {
		return false, errors.New("gate backend down")
	}), nil)

	sweeper.runOnce(context.Background())

	var count int64
	db.Model(&models.SessionRecording{}).Where("session_id = ?", session).Count(&count)
	if count != 1 {
		t.Error("gate error must fail open (workspace still indexed)")
	}
}
