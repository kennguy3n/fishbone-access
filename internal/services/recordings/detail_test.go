package recordings

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

func TestGetRecordingReturnsTimelineWithDenyFlag(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	target := seedTarget(t, db, ws, "db", "ssh")
	start := time.Now().Add(-time.Hour).UTC()
	end := start.Add(time.Minute)
	session := seedSession(t, db, ws, target, "alice@acme.io", "ssh", models.PAMSessionClosed, start, &end)
	seedCommand(t, db, ws, session, 1, "ls", models.PAMDecisionAllow, "")
	seedCommand(t, db, ws, session, 2, "rm -rf /", models.PAMDecisionDeny, "destructive")

	svc := NewService(db)
	if err := svc.IndexSession(context.Background(), ws, session); err != nil {
		t.Fatalf("index: %v", err)
	}

	detail, err := svc.GetRecording(context.Background(), ws, session)
	if err != nil {
		t.Fatalf("GetRecording: %v", err)
	}
	if len(detail.Timeline) != 2 {
		t.Fatalf("timeline len = %d, want 2", len(detail.Timeline))
	}
	if detail.Timeline[0].Seq != 1 || detail.Timeline[1].Seq != 2 {
		t.Errorf("timeline not ordered by seq: %+v", detail.Timeline)
	}
	if detail.Timeline[0].Denied {
		t.Error("first command should not be denied")
	}
	if !detail.Timeline[1].Denied {
		t.Error("second command should be flagged denied")
	}
}

func TestGetRecordingNotFound(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	svc := NewService(db)
	_, err := svc.GetRecording(context.Background(), ws, uuid.New())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestLoadFramesDecodesAndVerifies(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	target := seedTarget(t, db, ws, "db", "ssh")
	start := time.Now().Add(-time.Hour).UTC()
	end := start.Add(time.Minute)
	session := seedSession(t, db, ws, target, "alice@acme.io", "ssh", models.PAMSessionClosed, start, &end)

	blob, sha := buildBlob(t,
		frame('I', start, "uptime\r"),
		frame('O', start.Add(time.Second), "load average: 0.1\n"),
	)
	seedRecordingAnchor(t, db, ws, session, sha, int64(len(blob)), false)
	store := newFakeStore()
	store.put(session.String(), blob)
	metrics := &fakeMetrics{}
	svc := NewService(db, WithReplayReader(store), WithMetrics(metrics))
	if err := svc.IndexSession(context.Background(), ws, session); err != nil {
		t.Fatalf("index: %v", err)
	}

	stream, err := svc.LoadFrames(context.Background(), ws, session)
	if err != nil {
		t.Fatalf("LoadFrames: %v", err)
	}
	if len(stream.Frames) != 2 {
		t.Fatalf("frames = %d, want 2", len(stream.Frames))
	}
	if !stream.Anchored || !stream.Verified {
		t.Errorf("anchored=%v verified=%v, want both true", stream.Anchored, stream.Verified)
	}
	if stream.Frames[0].Direction != "input" || stream.Frames[1].Direction != "output" {
		t.Errorf("directions = %q,%q", stream.Frames[0].Direction, stream.Frames[1].Direction)
	}
}

// wsFakeStore is a fakeStore that also implements the optional
// workspaceReplayReader fast path, recording the workspace it was asked for so
// the test can assert the service used the lookup-skipping path.
type wsFakeStore struct {
	*fakeStore
	gotWorkspace string
}

func (f *wsFakeStore) GetReplayForWorkspace(ctx context.Context, workspaceID, sessionID string) (io.ReadCloser, error) {
	f.gotWorkspace = workspaceID
	return f.GetReplay(ctx, sessionID)
}

func TestLoadFramesUsesWorkspaceFastPath(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	target := seedTarget(t, db, ws, "db", "ssh")
	start := time.Now().Add(-time.Hour).UTC()
	end := start.Add(time.Minute)
	session := seedSession(t, db, ws, target, "alice@acme.io", "ssh", models.PAMSessionClosed, start, &end)

	blob, sha := buildBlob(t, frame('I', start, "whoami\r"))
	seedRecordingAnchor(t, db, ws, session, sha, int64(len(blob)), false)
	store := &wsFakeStore{fakeStore: newFakeStore()}
	store.put(session.String(), blob)
	svc := NewService(db, WithReplayReader(store))
	if err := svc.IndexSession(context.Background(), ws, session); err != nil {
		t.Fatalf("index: %v", err)
	}

	stream, err := svc.LoadFrames(context.Background(), ws, session)
	if err != nil {
		t.Fatalf("LoadFrames: %v", err)
	}
	if len(stream.Frames) != 1 {
		t.Fatalf("frames = %d, want 1", len(stream.Frames))
	}
	if store.gotWorkspace != ws.String() {
		t.Errorf("fast path workspace = %q, want %q", store.gotWorkspace, ws.String())
	}
}

func TestLoadFramesBlobPrunedUnavailable(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	target := seedTarget(t, db, ws, "db", "ssh")
	start := time.Now().Add(-time.Hour).UTC()
	end := start.Add(time.Minute)
	session := seedSession(t, db, ws, target, "alice@acme.io", "ssh", models.PAMSessionClosed, start, &end)
	svc := NewService(db)
	if err := svc.IndexSession(context.Background(), ws, session); err != nil {
		t.Fatalf("index: %v", err)
	}
	// Simulate a tiered-out blob.
	if err := db.Model(&models.SessionRecording{}).
		Where("session_id = ?", session).
		Update("blob_pruned", true).Error; err != nil {
		t.Fatalf("mark pruned: %v", err)
	}
	_, err := svc.LoadFrames(context.Background(), ws, session)
	if !errors.Is(err, ErrBlobUnavailable) {
		t.Fatalf("err = %v, want ErrBlobUnavailable", err)
	}
}
