package models

import (
	"time"

	"github.com/google/uuid"
)

// SessionRecording is the light, searchable PROJECTION of a single PAM session
// recording. The heavy, replayable bytes live in the ReplayStore (FS/S3) keyed
// by ReplayKey; this row is the queryable forensic metadata the console and an
// auditor search over — who ran the session, against what target, when, how
// many commands/denies, the integrity digest, and the extracted command/
// keystroke text (SearchText) that backs full-text search.
//
// It is populated by the recordings Indexer (internal/services/recordings),
// which is idempotent: re-indexing a session UPSERTs this row on
// (WorkspaceID, SessionID) rather than inserting a duplicate. The retention
// prune sweep tiers the heavy blob away (sets BlobPruned) while preserving this
// row and the audit-chain event, so forensic history survives blob expiry.
//
// The production schema is internal/migrations/0060_session_recordings.sql; the
// Postgres FTS GIN index (0061) is the only piece not represented here because
// AutoMigrate (the SQLite test path) has no tsvector — the search service falls
// back to LIKE there.
type SessionRecording struct {
	Base
	// WorkspaceID is the owning tenant; the (WorkspaceID, SessionID) pair is the
	// idempotent upsert key and the RLS isolation key.
	WorkspaceID uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:uq_session_recordings_session,priority:1,where:deleted_at IS NULL;index:idx_session_recordings_ws_started,priority:1" json:"workspace_id"`
	// SessionID is the PAM session this recording belongs to.
	SessionID uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:uq_session_recordings_session,priority:2,where:deleted_at IS NULL" json:"session_id"`
	// TargetID is the privileged target the session connected to (nullable: a
	// session whose target was later deleted still has a recording to replay).
	TargetID *uuid.UUID `gorm:"type:uuid" json:"target_id,omitempty"`
	// Operator is the subject (operator identity) that ran the session.
	Operator string `gorm:"not null;default:''" json:"operator"`
	// TargetName is the human-readable target name, denormalised for cheap
	// listing/search without a join.
	TargetName string `gorm:"not null;default:''" json:"target_name"`
	// Protocol is the session protocol (ssh, postgres, ...).
	Protocol string `gorm:"not null;default:''" json:"protocol"`
	// State is the session's terminal state at index time (closed, terminated).
	State string `gorm:"not null;default:''" json:"state"`
	// ClientAddr is the operator's client address captured at session start.
	ClientAddr string `gorm:"not null;default:''" json:"client_addr"`
	// StartedAt / EndedAt bound the session; DurationMillis is the cached span so
	// the console need not compute it per row.
	StartedAt     *time.Time `json:"started_at,omitempty"`
	EndedAt       *time.Time `json:"ended_at,omitempty"`
	DurationMillis int64     `gorm:"column:duration_ms;not null;default:0" json:"duration_ms"`
	// CommandCount / DenyCount are the per-session command totals (DenyCount is
	// the policy-denied subset surfaced in the timeline).
	CommandCount int `gorm:"not null;default:0" json:"command_count"`
	DenyCount    int `gorm:"not null;default:0" json:"deny_count"`
	// FrameCount / Bytes describe the decoded recording; Truncated reports the
	// gateway size cap dropped trailing payload.
	FrameCount int   `gorm:"not null;default:0" json:"frame_count"`
	Bytes      int64 `gorm:"not null;default:0" json:"bytes"`
	Truncated  bool  `gorm:"not null;default:false" json:"truncated"`
	// ReplayKey is the canonical ReplayStore key (gateway.ReplayKey) for the
	// heavy blob; cleared semantics are carried by BlobPruned, not by blanking
	// this, so the original location stays auditable.
	ReplayKey string `gorm:"not null;default:''" json:"replay_key"`
	// SHA256 is the hex digest the gateway anchored in the audit chain;
	// SHA256Verified records whether the indexer re-hashed the blob and it
	// matched (the tamper-evidence signal surfaced in the UI).
	SHA256         string `gorm:"column:sha256;not null;default:''" json:"sha256"`
	SHA256Verified bool   `gorm:"column:sha256_verified;not null;default:false" json:"sha256_verified"`
	// SearchText is the concatenated, normalised command + keystroke text that
	// backs full-text search (Postgres tsvector / SQLite LIKE). It never holds
	// raw output bytes — only operator-issued commands/keystrokes.
	SearchText string `gorm:"not null;default:''" json:"-"`
	// IndexedAt is when the indexer last projected this session.
	IndexedAt *time.Time `json:"indexed_at,omitempty"`
	// BlobPruned reports the retention sweep tiered the heavy blob away;
	// BlobPrunedAt is when. The row and audit event are preserved regardless.
	BlobPruned   bool       `gorm:"not null;default:false;index:idx_session_recordings_prune,priority:1" json:"blob_pruned"`
	BlobPrunedAt *time.Time `json:"blob_pruned_at,omitempty"`
}

// TableName pins the table so GORM's pluraliser cannot drift from the migration.
func (SessionRecording) TableName() string { return "session_recordings" }

// RecordingRetentionPolicy is a workspace's OVERRIDE of the default recording
// retention window. When a workspace has no row, the prune sweep uses the
// plan/global default from config (ACCESS_RECORDING_RETENTION_DAYS), so the
// common case needs no row (NoOps default). RetentionDays = 0 means "retain
// indefinitely" — an explicit opt-out for a long compliance hold.
//
// Production schema: internal/migrations/0062_recording_retention_policies.sql.
// There is exactly one row per workspace (WorkspaceID is the primary key), so
// this does not embed Base.
type RecordingRetentionPolicy struct {
	WorkspaceID   uuid.UUID `gorm:"type:uuid;primaryKey" json:"workspace_id"`
	RetentionDays int       `gorm:"not null;default:0" json:"retention_days"`
	UpdatedBy     string    `gorm:"not null;default:''" json:"updated_by"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// TableName pins the table name.
func (RecordingRetentionPolicy) TableName() string { return "recording_retention_policies" }
