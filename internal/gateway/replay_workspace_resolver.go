package gateway

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// This file adds the production SessionWorkspaceResolver the EncryptingReplayStore
// needs to derive a recording's per-workspace DEK. It is additive (a new file,
// new type) and reads only the pam_sessions row the recorder already wrote, so
// it introduces no new schema and no change to recorder.go.

// GormSessionWorkspaceResolver resolves a session id to its owning workspace id
// via the pam_sessions table. The encrypting replay decorator uses it on both
// the gateway write path and the control-plane read path so a blob is always
// sealed/opened under the DEK of the workspace that owns the session.
type GormSessionWorkspaceResolver struct {
	db *gorm.DB
}

// NewGormSessionWorkspaceResolver builds a resolver over the shared pool.
func NewGormSessionWorkspaceResolver(db *gorm.DB) *GormSessionWorkspaceResolver {
	return &GormSessionWorkspaceResolver{db: db}
}

// WorkspaceForSession returns the canonical workspace UUID string that owns
// sessionID. It runs an UNSCOPED lookup keyed only by primary key so it works
// on both the gateway write path (no tenant GUC set) and the API read path; the
// session id is itself an unguessable UUID minted by the broker, and the caller
// always pairs the result with an AAD that binds the workspace+session, so a
// wrong workspace cannot open another tenant's blob.
//
// Unscoped() is load-bearing: PAMSession embeds Base (gorm.DeletedAt), so a
// default query is implicitly WHERE deleted_at IS NULL. The DEK binding must
// survive a session being soft-deleted — the recording blob still exists and
// must stay decryptable for forensic replay/retention — so the resolver must
// find the row by primary key regardless of soft-delete state.
func (r *GormSessionWorkspaceResolver) WorkspaceForSession(ctx context.Context, sessionID string) (string, error) {
	if r == nil || r.db == nil {
		return "", errors.New("gateway: GormSessionWorkspaceResolver: nil db")
	}
	id, err := uuid.Parse(sessionID)
	if err != nil {
		return "", fmt.Errorf("gateway: GormSessionWorkspaceResolver: bad session id %q: %w", sessionID, err)
	}
	var session models.PAMSession
	if err := r.db.Unscoped().WithContext(ctx).
		Select("workspace_id").
		Where("id = ?", id).
		First(&session).Error; err != nil {
		return "", fmt.Errorf("gateway: GormSessionWorkspaceResolver: lookup %s: %w", sessionID, err)
	}
	return session.WorkspaceID.String(), nil
}

// Compile-time assertion that the resolver satisfies the decorator's seam.
var _ SessionWorkspaceResolver = (*GormSessionWorkspaceResolver)(nil)
