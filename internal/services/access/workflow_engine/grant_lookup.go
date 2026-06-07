package workflow_engine

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// GormGrantLookup is the production grantLookup over a GORM handle. Lookups are
// workspace-scoped so a cross-tenant grant id is invisible.
type GormGrantLookup struct {
	db *gorm.DB
}

// NewGormGrantLookup builds a lookup over the given handle.
func NewGormGrantLookup(db *gorm.DB) *GormGrantLookup {
	return &GormGrantLookup{db: db}
}

// GetGrant loads one grant scoped to the workspace. A missing grant returns a
// wrapped gorm.ErrRecordNotFound so callers can decide how to treat it (the
// review sweep logs and skips).
func (l *GormGrantLookup) GetGrant(ctx context.Context, workspaceID, grantID uuid.UUID) (*models.AccessGrant, error) {
	if l == nil || l.db == nil {
		return nil, fmt.Errorf("workflow_engine: GormGrantLookup not initialised")
	}
	var grant models.AccessGrant
	err := l.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, grantID).
		Take(&grant).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("workflow_engine: grant %s not found in workspace: %w", grantID, err)
	}
	if err != nil {
		return nil, fmt.Errorf("workflow_engine: load grant %s: %w", grantID, err)
	}
	return &grant, nil
}

// Ensure GormGrantLookup satisfies the grantLookup contract.
var _ grantLookup = (*GormGrantLookup)(nil)
