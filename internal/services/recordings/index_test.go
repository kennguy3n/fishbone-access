package recordings

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

func TestIndexSessionProjectsMetadataAndCommands(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	target := seedTarget(t, db, ws, "prod-db", "ssh")
	start := time.Now().Add(-30 * time.Minute).UTC()
	end := start.Add(10 * time.Minute)
	session := seedSession(t, db, ws, target, "alice@acme.io", "ssh", models.PAMSessionClosed, start, &end)

	seedCommand(t, db, ws, session, 1, "whoami", models.PAMDecisionAllow, "")
	seedCommand(t, db, ws, session, 2, "sudo rm -rf /etc", models.PAMDecisionDeny, "blocked by policy")

	// Build a recording blob with operator keystrokes so enrichment runs.
	at := start
	blob, sha := buildBlob(t,
		frame('I', at, "cat /etc/passwd\r"),
		frame('O', at.Add(time.Second), "root:x:0:0:root:/root:/bin/bash\n"),
	)
	seedRecordingAnchor(t, db, ws, session, sha, int64(len(blob)), false)

	store := newFakeStore()
	store.put(session.String(), blob)
	metrics := &fakeMetrics{}
	svc := NewService(db, WithReplayReader(store), WithMetrics(metrics))

	if err := svc.IndexSession(context.Background(), ws, session); err != nil {
		t.Fatalf("IndexSession: %v", err)
	}

	var rec models.SessionRecording
	if err := db.Where("workspace_id = ? AND session_id = ?", ws, session).First(&rec).Error; err != nil {
		t.Fatalf("load recording: %v", err)
	}

	if rec.Operator != "alice@acme.io" {
		t.Errorf("operator = %q, want alice@acme.io", rec.Operator)
	}
	if rec.TargetName != "prod-db" {
		t.Errorf("target name = %q, want prod-db", rec.TargetName)
	}
	if rec.Protocol != "ssh" {
		t.Errorf("protocol = %q, want ssh", rec.Protocol)
	}
	if rec.CommandCount != 2 {
		t.Errorf("command count = %d, want 2", rec.CommandCount)
	}
	if rec.DenyCount != 1 {
		t.Errorf("deny count = %d, want 1", rec.DenyCount)
	}
	if rec.DurationMillis != end.Sub(start).Milliseconds() {
		t.Errorf("duration = %d, want %d", rec.DurationMillis, end.Sub(start).Milliseconds())
	}
	if rec.SHA256 != sha {
		t.Errorf("sha256 = %q, want %q", rec.SHA256, sha)
	}
	if !rec.SHA256Verified {
		t.Error("sha256_verified = false, want true (digest matches anchor)")
	}
	if rec.FrameCount != 2 {
		t.Errorf("frame count = %d, want 2", rec.FrameCount)
	}
	// Search text must contain commands AND extracted keystrokes, never output.
	if !strings.Contains(rec.SearchText, "whoami") || !strings.Contains(rec.SearchText, "sudo rm -rf /etc") {
		t.Errorf("search text missing commands: %q", rec.SearchText)
	}
	if !strings.Contains(rec.SearchText, "cat /etc/passwd") {
		t.Errorf("search text missing keystrokes: %q", rec.SearchText)
	}
	if strings.Contains(rec.SearchText, "root:x:0:0") {
		t.Errorf("search text must NOT contain target output: %q", rec.SearchText)
	}
	if got, _, _ := metrics.snapshot(); got != 0 {
		// IndexSession does not bump the aggregate counter; only the batch does.
		t.Errorf("indexed metric = %d, want 0 for single IndexSession", got)
	}
}

func TestIndexSessionReindexIsIdempotent(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	target := seedTarget(t, db, ws, "prod-db", "ssh")
	start := time.Now().Add(-time.Hour).UTC()
	end := start.Add(time.Minute)
	session := seedSession(t, db, ws, target, "bob@acme.io", "ssh", models.PAMSessionClosed, start, &end)
	seedCommand(t, db, ws, session, 1, "ls", models.PAMDecisionAllow, "")

	svc := NewService(db)
	if err := svc.IndexSession(context.Background(), ws, session); err != nil {
		t.Fatalf("first index: %v", err)
	}
	var first models.SessionRecording
	if err := db.Where("session_id = ?", session).First(&first).Error; err != nil {
		t.Fatalf("load: %v", err)
	}
	// Re-index after another command lands; the row updates in place.
	seedCommand(t, db, ws, session, 2, "pwd", models.PAMDecisionAllow, "")
	if err := svc.IndexSession(context.Background(), ws, session); err != nil {
		t.Fatalf("re-index: %v", err)
	}

	var count int64
	if err := db.Model(&models.SessionRecording{}).Where("session_id = ?", session).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 row after re-index, got %d", count)
	}
	var second models.SessionRecording
	if err := db.Where("session_id = ?", session).First(&second).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if second.ID != first.ID {
		t.Errorf("row identity changed on re-index: %s -> %s", first.ID, second.ID)
	}
	if second.CommandCount != 2 {
		t.Errorf("re-index command count = %d, want 2", second.CommandCount)
	}
}

func TestIndexSessionTamperDetected(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	target := seedTarget(t, db, ws, "db", "ssh")
	start := time.Now().Add(-time.Hour).UTC()
	end := start.Add(time.Minute)
	session := seedSession(t, db, ws, target, "eve@acme.io", "ssh", models.PAMSessionClosed, start, &end)

	blob, _ := buildBlob(t, frame('I', start, "id\r"))
	// Anchor a DIFFERENT digest than the blob actually hashes to → tamper.
	seedRecordingAnchor(t, db, ws, session, strings.Repeat("a", 64), int64(len(blob)), false)

	store := newFakeStore()
	store.put(session.String(), blob)
	metrics := &fakeMetrics{}
	svc := NewService(db, WithReplayReader(store), WithMetrics(metrics))

	if err := svc.IndexSession(context.Background(), ws, session); err != nil {
		t.Fatalf("IndexSession: %v", err)
	}
	var rec models.SessionRecording
	if err := db.Where("session_id = ?", session).First(&rec).Error; err != nil {
		t.Fatalf("load: %v", err)
	}
	if rec.SHA256Verified {
		t.Error("sha256_verified = true, want false (digest mismatch)")
	}
	if _, _, tamper := metrics.snapshot(); tamper != 1 {
		t.Errorf("tamper metric = %d, want 1", tamper)
	}
}

// TestIndexSessionNoTamperWhenAnchorHasNoDigest guards against a false-positive
// tamper alarm: when the recording audit event EXISTS but carries no SHA-256
// (the gateway anchored the event without a digest), there is nothing to verify
// against, so enrichment must NOT flag tampering. Without the
// `anchor.SHA256 != ""` guard the counter would fire fleet-wide for every such
// recording.
func TestIndexSessionNoTamperWhenAnchorHasNoDigest(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	target := seedTarget(t, db, ws, "db", "ssh")
	start := time.Now().Add(-time.Hour).UTC()
	end := start.Add(time.Minute)
	session := seedSession(t, db, ws, target, "mallory@acme.io", "ssh", models.PAMSessionClosed, start, &end)

	blob, _ := buildBlob(t, frame('I', start, "uptime\r"))
	// Anchor the recording event but with an EMPTY digest (Found=true, SHA256="").
	seedRecordingAnchor(t, db, ws, session, "", int64(len(blob)), false)

	store := newFakeStore()
	store.put(session.String(), blob)
	metrics := &fakeMetrics{}
	svc := NewService(db, WithReplayReader(store), WithMetrics(metrics))

	if err := svc.IndexSession(context.Background(), ws, session); err != nil {
		t.Fatalf("IndexSession: %v", err)
	}
	var rec models.SessionRecording
	if err := db.Where("session_id = ?", session).First(&rec).Error; err != nil {
		t.Fatalf("load: %v", err)
	}
	if rec.SHA256Verified {
		t.Error("sha256_verified = true, want false (no anchor digest to verify against)")
	}
	if _, _, tamper := metrics.snapshot(); tamper != 0 {
		t.Errorf("tamper metric = %d, want 0 (no digest must not be treated as tampering)", tamper)
	}
	// Enrichment is fail-open: the blob was still decoded for frame count + search.
	if rec.FrameCount != 1 {
		t.Errorf("frame count = %d, want 1 (enrichment still runs without an anchor digest)", rec.FrameCount)
	}
	if !strings.Contains(rec.SearchText, "uptime") {
		t.Errorf("search text missing keystrokes: %q", rec.SearchText)
	}
}

func TestIndexClosedSessionsSkipsActiveAndCountsAggregate(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "acme")
	target := seedTarget(t, db, ws, "db", "ssh")
	start := time.Now().Add(-time.Hour).UTC()
	end := start.Add(time.Minute)

	closed1 := seedSession(t, db, ws, target, "a@acme.io", "ssh", models.PAMSessionClosed, start, &end)
	closed2 := seedSession(t, db, ws, target, "b@acme.io", "ssh", models.PAMSessionClosed, start, &end)
	active := seedSession(t, db, ws, target, "c@acme.io", "ssh", models.PAMSessionActive, start, nil)
	_ = closed1
	_ = closed2

	metrics := &fakeMetrics{}
	svc := NewService(db, WithMetrics(metrics))
	n, err := svc.IndexClosedSessions(context.Background(), ws, 50)
	if err != nil {
		t.Fatalf("IndexClosedSessions: %v", err)
	}
	if n != 2 {
		t.Fatalf("indexed = %d, want 2 (active session must be skipped)", n)
	}
	var activeRow int64
	db.Model(&models.SessionRecording{}).Where("session_id = ?", active).Count(&activeRow)
	if activeRow != 0 {
		t.Error("active session was indexed; it must be skipped until closed")
	}
	if indexed, _, _ := metrics.snapshot(); indexed != 2 {
		t.Errorf("indexed metric = %d, want 2", indexed)
	}

	// Second run indexes nothing new (idempotent backlog drain).
	n2, err := svc.IndexClosedSessions(context.Background(), ws, 50)
	if err != nil {
		t.Fatalf("second IndexClosedSessions: %v", err)
	}
	if n2 != 0 {
		t.Errorf("second run indexed = %d, want 0", n2)
	}
}
