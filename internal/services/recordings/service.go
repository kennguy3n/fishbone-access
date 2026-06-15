// Package recordings turns the PAM gateway's session recordings from an
// opaque, integrity-only blob into a SEARCHABLE forensic store. The gateway
// captures every privileged session as a direction-tagged, timestamped framed
// blob in a ReplayStore (FS/S3) and anchors its SHA-256 in the per-workspace
// audit hash chain; this package projects each finished session into a light,
// queryable row (models.SessionRecording) an auditor or SME admin can search by
// operator/target/protocol/time and by full-text over the commands executed,
// then stream and replay.
//
// Layering and cost discipline (5,000-SME fleet):
//   - INDEXING is a pure-DB projection by default (operator/target/timing +
//     command counts + the command text from pam_session_commands + the integrity
//     digest from the audit chain), so the common path touches no blob. When a
//     ReplayReader is wired the indexer ALSO mines the framed INPUT bytes for
//     keystroke text and records the live frame count + tamper status — bounded,
//     once-per-session work the background sweep runs hibernation-gated.
//   - SEARCH is Postgres FTS (to_tsvector/GIN, migration 0061) with a SQLite
//     LIKE fallback for the test path; no new infrastructure.
//   - RETENTION tiers the heavy blob out of object storage past a per-workspace
//     window while PRESERVING the metadata row AND the audit event, so forensic
//     history and the integrity record survive blob expiry.
//
// The package never logs recording contents and never indexes target OUTPUT
// (which holds secrets/query results) — only operator INPUT and the already
// policy-gated command rows.
package recordings

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Sentinel errors the handlers map to HTTP status codes.
var (
	// ErrValidation is a bad caller input (empty id, negative retention, …).
	ErrValidation = errors.New("recordings: validation error")
	// ErrNotFound is returned when no indexed recording exists for the session.
	ErrNotFound = errors.New("recordings: recording not found")
	// ErrBlobUnavailable is returned when the replay blob cannot be served:
	// either no ReplayReader is configured, or the blob was tiered out by the
	// retention sweep (BlobPruned). The metadata + command timeline remain
	// available; only the byte-level replay is gone.
	ErrBlobUnavailable = errors.New("recordings: replay blob unavailable")
)

// ReplayReader fetches a recording's stored bytes by session id. The gateway's
// FilesystemReplayStore / S3ReplayStore / EncryptingReplayStore all satisfy it;
// the encrypting decorator transparently decrypts on read so this package only
// ever sees plaintext frames.
type ReplayReader interface {
	GetReplay(ctx context.Context, sessionID string) (io.ReadCloser, error)
}

// workspaceReplayReader is an optional fast path: a reader that can fetch a
// blob for a caller that already knows the owning workspace, skipping the
// reader's own workspace lookup. The at-rest EncryptingReplayStore implements
// it (its plain GetReplay otherwise re-resolves the workspace from the DB on
// every read). Honoured via getReplay; readers that don't implement it fall
// back to GetReplay, so this stays an optimisation, never a requirement.
type workspaceReplayReader interface {
	GetReplayForWorkspace(ctx context.Context, workspaceID, sessionID string) (io.ReadCloser, error)
}

// getReplay reads a recording blob, using the workspace-aware fast path when
// the configured reader supports it (the caller already loaded the workspace),
// and otherwise the plain by-session read.
func (s *Service) getReplay(ctx context.Context, workspaceID, sessionID uuid.UUID) (io.ReadCloser, error) {
	if wr, ok := s.reader.(workspaceReplayReader); ok && workspaceID != uuid.Nil {
		return wr.GetReplayForWorkspace(ctx, workspaceID.String(), sessionID.String())
	}
	return s.reader.GetReplay(ctx, sessionID.String())
}

// ReplayDeleter tiers a recording's heavy blob out of storage. The retention
// sweep depends on this narrow capability so it can prune any backend; the
// gateway stores implement it in replay_prune.go. Idempotent: deleting an
// already-absent blob succeeds.
type ReplayDeleter interface {
	DeleteReplay(ctx context.Context, sessionID string) error
}

// Metrics is the aggregate-only observability seam (no per-tenant labels, to
// hold cardinality at 5,000 tenants). observability.Metrics satisfies it; a nil
// Metrics disables instrumentation without branching at every call site.
type Metrics interface {
	AddRecordingsIndexed(n int)
	AddRecordingsPruned(n int)
	IncRecordingTamperDetected()
}

// Service is the recordings forensic store: indexer, full-text search, replay
// loader, and retention/tiering. It is safe for concurrent use (it holds only
// immutable handles); all per-request state is passed in.
type Service struct {
	db      *gorm.DB
	reader  ReplayReader
	deleter ReplayDeleter
	metrics Metrics
	now     func() time.Time

	// maxKeystrokeText caps the extracted keystroke text per recording so a
	// pathological session cannot bloat the row / FTS index. 0 uses the default.
	maxKeystrokeText int
}

// Option configures a Service at construction.
type Option func(*Service)

// WithReplayReader wires the blob reader used for keystroke enrichment at index
// time and for serving frames to the replay player. Without it the indexer is a
// pure-DB projection and the stream endpoint reports the blob unavailable.
func WithReplayReader(r ReplayReader) Option {
	return func(s *Service) {
		if r != nil {
			s.reader = r
		}
	}
}

// WithReplayDeleter wires the blob deleter the retention sweep uses to tier
// recordings out of storage. Without it the sweep degrades to marking rows
// pruned only when it can also delete (it cannot), so it is required to enable
// real tiering; absent it, PruneExpiredBlobs is a no-op that reports zero.
func WithReplayDeleter(d ReplayDeleter) Option {
	return func(s *Service) {
		if d != nil {
			s.deleter = d
		}
	}
}

// WithMetrics wires aggregate observability counters.
func WithMetrics(m Metrics) Option {
	return func(s *Service) {
		if m != nil {
			s.metrics = m
		}
	}
}

// WithClock overrides the time source (tests).
func WithClock(now func() time.Time) Option {
	return func(s *Service) {
		if now != nil {
			s.now = now
		}
	}
}

// WithMaxKeystrokeText overrides the per-recording keystroke-text cap.
func WithMaxKeystrokeText(n int) Option {
	return func(s *Service) {
		if n > 0 {
			s.maxKeystrokeText = n
		}
	}
}

// defaultMaxKeystrokeText bounds extracted keystroke text per recording (256
// KiB of decoded input is far more than any human session, but caps a
// pathological/automated one).
const defaultMaxKeystrokeText = 256 << 10

// NewService builds the recordings service over the given DB handle.
func NewService(db *gorm.DB, opts ...Option) *Service {
	s := &Service{
		db:               db,
		now:              time.Now,
		maxKeystrokeText: defaultMaxKeystrokeText,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// isPostgres reports whether the active dialect is Postgres, so the FTS path
// (and any other dialect-specific SQL) is used only where it exists; the test
// path runs on SQLite and falls back to portable SQL.
func isPostgres(db *gorm.DB) bool {
	return db != nil && db.Dialector != nil && db.Name() == "postgres"
}
