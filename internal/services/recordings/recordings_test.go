package recordings

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/database"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
)

// --- test harness ---------------------------------------------------------

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := database.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := database.AutoMigrate(db); err != nil {
		t.Fatalf("auto-migrate: %v", err)
	}
	return db
}

func seedWorkspace(t *testing.T, db *gorm.DB, name string) uuid.UUID {
	t.Helper()
	ws := &models.Workspace{Name: name, IAMCoreTenantID: name, Plan: "base"}
	if err := db.Create(ws).Error; err != nil {
		t.Fatalf("seed workspace: %v", err)
	}
	return ws.ID
}

func seedTarget(t *testing.T, db *gorm.DB, ws uuid.UUID, name, proto string) uuid.UUID {
	t.Helper()
	tg := &models.PAMTarget{WorkspaceID: ws, Name: name, Protocol: proto, Address: "10.0.0.1:22"}
	if err := db.Create(tg).Error; err != nil {
		t.Fatalf("seed target: %v", err)
	}
	return tg.ID
}

func seedSession(t *testing.T, db *gorm.DB, ws, target uuid.UUID, subject, proto, state string, started time.Time, ended *time.Time) uuid.UUID {
	t.Helper()
	s := &models.PAMSession{
		WorkspaceID: ws,
		TargetID:    target,
		Subject:     subject,
		Protocol:    proto,
		State:       state,
		ClientAddr:  "203.0.113.5",
		ReplayKey:   "",
		StartedAt:   started,
		EndedAt:     ended,
	}
	if err := db.Create(s).Error; err != nil {
		t.Fatalf("seed session: %v", err)
	}
	// ReplayKey mirrors the canonical key the gateway records under.
	s.ReplayKey = "sessions/" + s.ID.String() + "/replay.bin"
	if err := db.Save(s).Error; err != nil {
		t.Fatalf("set replay key: %v", err)
	}
	return s.ID
}

func seedCommand(t *testing.T, db *gorm.DB, ws, session uuid.UUID, seq int64, cmd, decision, reason string) {
	t.Helper()
	c := &models.PAMSessionCommand{
		WorkspaceID: ws,
		SessionID:   session,
		Seq:         seq,
		Command:     cmd,
		Decision:    decision,
		Reason:      reason,
	}
	if err := db.Create(c).Error; err != nil {
		t.Fatalf("seed command: %v", err)
	}
}

// seedRecordingAnchor appends the gateway's recording event to the workspace
// audit chain, the source the indexer recovers the integrity digest from.
func seedRecordingAnchor(t *testing.T, db *gorm.DB, ws, session uuid.UUID, sha string, nbytes int64, truncated bool) {
	t.Helper()
	md, err := json.Marshal(map[string]any{
		"session_id": session.String(),
		"sha256":     sha,
		"bytes":      nbytes,
		"truncated":  truncated,
	})
	if err != nil {
		t.Fatalf("marshal anchor meta: %v", err)
	}
	if err := lifecycle.AppendAudit(context.Background(), db, time.Now(), lifecycle.AuditInput{
		WorkspaceID: ws,
		Actor:       "gateway",
		Action:      recordingAuditAction,
		TargetRef:   session.String(),
		Metadata:    datatypes.JSON(md),
	}); err != nil {
		t.Fatalf("append anchor: %v", err)
	}
}

// --- frame blob builder ----------------------------------------------------

func frame(dir byte, at time.Time, payload string) []byte {
	var hdr [13]byte
	hdr[0] = dir
	binary.BigEndian.PutUint64(hdr[1:9], uint64(at.UnixNano()))
	binary.BigEndian.PutUint32(hdr[9:13], uint32(len(payload)))
	return append(hdr[:], []byte(payload)...)
}

// buildBlob assembles a recording blob from input/output frames and returns the
// bytes plus their SHA-256 (hex), mirroring what the gateway recorder wrote.
func buildBlob(t *testing.T, frames ...[]byte) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	for _, f := range frames {
		buf.Write(f)
	}
	sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(sum[:])
}

// --- fake replay store -----------------------------------------------------

// fakeStore is an in-memory ReplayReader + ReplayDeleter keyed by session id.
type fakeStore struct {
	mu      sync.Mutex
	blobs   map[string][]byte
	deletes int
}

func newFakeStore() *fakeStore { return &fakeStore{blobs: map[string][]byte{}} }

func (f *fakeStore) put(sessionID string, b []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blobs[sessionID] = b
}

func (f *fakeStore) GetReplay(_ context.Context, sessionID string) (io.ReadCloser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.blobs[sessionID]
	if !ok {
		return nil, io.EOF
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

func (f *fakeStore) DeleteReplay(_ context.Context, sessionID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.blobs, sessionID)
	f.deletes++
	return nil
}

func (f *fakeStore) has(sessionID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.blobs[sessionID]
	return ok
}

// --- fake metrics ----------------------------------------------------------

type fakeMetrics struct {
	mu      sync.Mutex
	indexed int
	pruned  int
	tamper  int
}

func (m *fakeMetrics) AddRecordingsIndexed(n int) { m.mu.Lock(); m.indexed += n; m.mu.Unlock() }
func (m *fakeMetrics) AddRecordingsPruned(n int)  { m.mu.Lock(); m.pruned += n; m.mu.Unlock() }
func (m *fakeMetrics) IncRecordingTamperDetected() { m.mu.Lock(); m.tamper++; m.mu.Unlock() }

func (m *fakeMetrics) snapshot() (int, int, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.indexed, m.pruned, m.tamper
}
