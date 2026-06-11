package compliance

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
)

// appendEventMeta appends a chained audit event carrying metadata, so tests can
// reproduce the pam.session.recording event the gateway emits at teardown.
func appendEventMeta(t *testing.T, db *gorm.DB, workspaceID uuid.UUID, action, target string, meta map[string]any) {
	t.Helper()
	raw, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal meta: %v", err)
	}
	if err := lifecycle.AppendAudit(context.Background(), db, time.Now(), lifecycle.AuditInput{
		WorkspaceID: workspaceID,
		Actor:       "tester",
		Action:      action,
		TargetRef:   target,
		Metadata:    datatypes.JSON(raw),
	}); err != nil {
		t.Fatalf("append event %q: %v", action, err)
	}
}

// TestClassifyPrivilegedActions locks in the action→kind mapping that lands PAM
// activity in the CC6.7 / A.8.2 control family. Before this, only pam.command
// was classified, so a session that opened and was recorded but ran no command
// produced zero privileged-access evidence.
func TestClassifyPrivilegedActions(t *testing.T) {
	cases := map[string]EvidenceKind{
		"pam.session.opened":     KindPrivilegedSession,
		"pam.session.closed":     KindPrivilegedSession,
		"pam.session.terminated": KindPrivilegedSession,
		"pam.session.paused":     KindPrivilegedSession,
		"pam.session.resumed":    KindPrivilegedSession,
		"pam.command":            KindPrivilegedCommand,
		"pam.session.recording":  KindPrivilegedRecording,
	}
	for action, want := range cases {
		if got := classify(action); got != want {
			t.Errorf("classify(%q) = %q, want %q", action, got, want)
		}
	}
}

// TestProjectRecordingRowParseError proves that a recording event whose metadata
// blob is unparseable still produces an indexed row (so it is never silently
// dropped) and is flagged with parse_error=true, while a well-formed row leaves
// the flag unset and omitted from JSON.
func TestProjectRecordingRowParseError(t *testing.T) {
	bad := projectRecordingRow(EvidenceRecord{
		ChainSeq:  7,
		ChainHash: "abc123",
		Metadata:  datatypes.JSON([]byte("{not valid json")),
	})
	if !bad.ParseError {
		t.Fatalf("malformed recording metadata should set parse_error")
	}
	if bad.SessionID != "" || bad.ReplayKey != "" || bad.SHA256 != "" {
		t.Errorf("malformed metadata should leave reference fields empty: %+v", bad)
	}
	if bad.ChainSeq != 7 || bad.ChainHash != "abc123" {
		t.Errorf("chain anchor must survive a metadata decode failure: %+v", bad)
	}
	if out, err := json.Marshal(bad); err != nil {
		t.Fatalf("marshal: %v", err)
	} else if !bytes.Contains(out, []byte(`"parse_error":true`)) {
		t.Errorf("parse_error=true must serialise: %s", out)
	}

	good := projectRecordingRow(EvidenceRecord{
		ChainSeq:  8,
		ChainHash: "def456",
		Metadata:  datatypes.JSON([]byte(`{"session_id":"s1","replay_key":"k","sha256":"h"}`)),
	})
	if good.ParseError {
		t.Fatalf("well-formed metadata must not set parse_error")
	}
	if out, err := json.Marshal(good); err != nil {
		t.Fatalf("marshal: %v", err)
	} else if bytes.Contains(out, []byte("parse_error")) {
		t.Errorf("parse_error must be omitted on the normal path: %s", out)
	}
}

// TestPrivilegedAccessCoverageCountsAndControls drives a full seeded-session
// shape of events through the projection and asserts the headline counts and
// that the privileged-access controls (CC6.7 / A.8.2 / PCI-10.2) are credited
// across frameworks.
func TestPrivilegedAccessCoverageCountsAndControls(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	ctx := context.Background()

	// One privileged session: opened → command → recording → closed.
	appendEvent(t, db, ws, "pam.session.opened", "target-1")
	appendEvent(t, db, ws, "pam.command", "target-1")
	appendEventMeta(t, db, ws, "pam.session.recording", "target-1", map[string]any{
		"session_id": "sess-1",
		"replay_key": "sessions/sess-1/replay.bin",
		"sha256":     "abc123",
		"bytes":      int64(42),
		"truncated":  false,
	})
	appendEvent(t, db, ws, "pam.session.closed", "target-1")
	// An unrelated controlled event must not be counted as privileged.
	appendEvent(t, db, ws, "policy.promoted", "p1")

	svc := NewEvidenceService(db)
	cov, err := svc.PrivilegedAccessCoverage(ctx, ws, nil, nil)
	if err != nil {
		t.Fatalf("PrivilegedAccessCoverage: %v", err)
	}

	if !cov.Monitored {
		t.Fatalf("expected Monitored=true")
	}
	if cov.Sessions != 2 { // opened + closed
		t.Errorf("Sessions = %d, want 2", cov.Sessions)
	}
	if cov.Commands != 1 {
		t.Errorf("Commands = %d, want 1", cov.Commands)
	}
	if cov.Recordings != 1 {
		t.Errorf("Recordings = %d, want 1", cov.Recordings)
	}
	if cov.EvidenceTotal != 4 {
		t.Errorf("EvidenceTotal = %d, want 4", cov.EvidenceTotal)
	}

	// CC6.7 (SOC2), A.8.2 (ISO), and 10.2 (PCI) must all appear and be covered.
	wantCovered := map[string]Framework{"CC6.7": FrameworkSOC2, "A.8.2": FrameworkISO27001, "10.2": FrameworkPCIDSS}
	seen := map[string]bool{}
	for _, c := range cov.Controls {
		if fw, ok := wantCovered[c.ID]; ok {
			if c.Framework != fw {
				t.Errorf("control %s framework = %q, want %q", c.ID, c.Framework, fw)
			}
			if !c.Covered {
				t.Errorf("control %s expected covered", c.ID)
			}
			seen[c.ID] = true
		}
	}
	for id := range wantCovered {
		if !seen[id] {
			t.Errorf("privileged-access control %s missing from coverage", id)
		}
	}
}

// TestPrivilegedAccessCoverageEmpty confirms a workspace with no PAM activity
// reports Monitored=false with zero counts (the pre-fix state), so the panel is
// honest rather than fabricating coverage.
func TestPrivilegedAccessCoverageEmpty(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-empty")
	appendEvent(t, db, ws, "policy.promoted", "p1") // controlled, but not privileged

	cov, err := NewEvidenceService(db).PrivilegedAccessCoverage(context.Background(), ws, nil, nil)
	if err != nil {
		t.Fatalf("PrivilegedAccessCoverage: %v", err)
	}
	if cov.Monitored || cov.EvidenceTotal != 0 || cov.Sessions != 0 || cov.Commands != 0 || cov.Recordings != 0 {
		t.Fatalf("expected zero privileged coverage, got %+v", cov)
	}
}

// TestPackIncludesRecordingReferences proves the evidence pack carries a
// pam-recordings.jsonl index that ties a CC6.7/A.8.2 record to a replayable,
// integrity-hashed recording — the auditor-facing deliverable.
func TestPackIncludesRecordingReferences(t *testing.T) {
	db := newTestDB(t)
	ws := seedWorkspace(t, db, "tenant-a")
	ctx := context.Background()

	appendEvent(t, db, ws, "pam.session.opened", "target-1")
	appendEventMeta(t, db, ws, "pam.session.recording", "target-1", map[string]any{
		"session_id": "sess-9",
		"replay_key": "sessions/sess-9/replay.bin",
		"sha256":     "deadbeef",
		"bytes":      int64(128),
		"truncated":  false,
	})
	appendEvent(t, db, ws, "pam.session.closed", "target-1")

	pw := NewPackWriter(db, NewEvidenceService(db))
	var buf bytes.Buffer
	if _, err := pw.WritePack(ctx, &buf, ExportOptions{WorkspaceID: ws, Framework: FrameworkSOC2, GeneratedBy: "auditor"}); err != nil {
		t.Fatalf("WritePack: %v", err)
	}

	files := readZip(t, buf.Bytes())
	raw, ok := files["pam-recordings.jsonl"]
	if !ok {
		t.Fatalf("pack missing pam-recordings.jsonl (have %v)", keys(files))
	}
	if countLines(raw) != 1 {
		t.Fatalf("expected exactly 1 recording row, got %d", countLines(raw))
	}
	var row recordingIndexRow
	if err := json.Unmarshal(bytes.TrimSpace(raw), &row); err != nil {
		t.Fatalf("recording row unmarshal: %v", err)
	}
	if row.SessionID != "sess-9" || row.ReplayKey != "sessions/sess-9/replay.bin" || row.SHA256 != "deadbeef" {
		t.Fatalf("recording row missing reference fields: %+v", row)
	}
	if row.Bytes != 128 {
		t.Errorf("recording row bytes = %d, want 128", row.Bytes)
	}
	if row.ParseError {
		t.Errorf("well-formed recording metadata should not set parse_error")
	}
	if row.ChainHash == "" {
		t.Errorf("recording row should carry its anchoring chain hash")
	}

	// README inventory should list the new file too.
	if !bytes.Contains(files["README.md"], []byte("`pam-recordings.jsonl`")) {
		t.Errorf("README Files section does not list pam-recordings.jsonl")
	}
}
