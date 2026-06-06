package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// AccessRequestService owns the access_requests + access_request_state_history
// tables and is the single source of truth for state transitions: every
// read-then-write is wrapped in a DB transaction and gated by Transition() so
// the FSM, the history trail, and the audit chain can never diverge.
//
// The service never calls connectors directly. Provisioning (the
// approved → provisioning → provisioned/provision_failed leg) is owned by
// AccessProvisioningService, which reuses TransitionInTx to flip state inside
// the same transaction that inserts the access_grants row.
type AccessRequestService struct {
	db  *gorm.DB
	now func() time.Time
}

// NewAccessRequestService returns a service backed by db, which must not be
// nil. The clock is time.Now; tests override it via SetClock.
func NewAccessRequestService(db *gorm.DB) *AccessRequestService {
	return &AccessRequestService{db: db, now: time.Now}
}

// SetClock overrides the time source. Intended for tests that pin timestamps.
func (s *AccessRequestService) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// CreateAccessRequestInput is the input contract for CreateRequest. WorkspaceID,
// RequesterID, ResourceRef and Role are required. TargetUserID defaults to
// RequesterID. ConnectorID is required before the request can be provisioned
// but may be nil for a pure approval-only workflow. RiskLevel/RiskFactors are
// optional decision-support inputs (low/medium/high) used by WorkflowService.
type CreateAccessRequestInput struct {
	WorkspaceID   uuid.UUID
	RequesterID   string
	TargetUserID  string
	ConnectorID   *uuid.UUID
	ResourceRef   string
	Role          string
	Justification string
	RiskLevel     string
	RiskFactors   []string
	ExpiresAt     *time.Time
}

// CreateRequest validates input, persists a new access_requests row in
// StateRequested, writes the initial "" → requested history row, and appends an
// audit event — all in a single transaction so a partial failure leaves no
// orphaned rows.
func (s *AccessRequestService) CreateRequest(ctx context.Context, in CreateAccessRequestInput) (*models.AccessRequest, error) {
	if in.WorkspaceID == uuid.Nil {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if in.RequesterID == "" {
		return nil, fmt.Errorf("%w: requester_id is required", ErrValidation)
	}
	if in.ResourceRef == "" {
		return nil, fmt.Errorf("%w: resource_ref is required", ErrValidation)
	}
	if in.Role == "" {
		return nil, fmt.Errorf("%w: role is required", ErrValidation)
	}
	target := in.TargetUserID
	if target == "" {
		target = in.RequesterID
	}

	now := s.now()
	req := &models.AccessRequest{
		WorkspaceID:   in.WorkspaceID,
		RequesterID:   in.RequesterID,
		TargetUserID:  target,
		ConnectorID:   in.ConnectorID,
		ResourceRef:   in.ResourceRef,
		Role:          in.Role,
		Justification: in.Justification,
		State:         StateRequested,
		RiskLevel:     in.RiskLevel,
	}
	if len(in.RiskFactors) > 0 {
		if b, err := json.Marshal(in.RiskFactors); err == nil {
			req.RiskFactors = datatypes.JSON(b)
		}
	}
	req.CreatedAt = now
	req.UpdatedAt = now
	if in.ExpiresAt != nil {
		req.ExpiresAt = in.ExpiresAt
	}

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(req).Error; err != nil {
			return fmt.Errorf("lifecycle: insert access_request: %w", err)
		}
		hist := &models.AccessRequestStateHistory{
			WorkspaceID: req.WorkspaceID,
			RequestID:   req.ID,
			FromState:   "",
			ToState:     StateRequested,
			Actor:       in.RequesterID,
			Reason:      "request created",
		}
		hist.CreatedAt = now
		hist.UpdatedAt = now
		if err := tx.Create(hist).Error; err != nil {
			return fmt.Errorf("lifecycle: insert state history: %w", err)
		}
		return appendAudit(ctx, tx, now, auditEntry{
			WorkspaceID: req.WorkspaceID,
			Actor:       in.RequesterID,
			Action:      "access_request.created",
			TargetRef:   req.ID.String(),
		})
	})
	if err != nil {
		return nil, err
	}
	return req, nil
}

// GetRequest loads one request scoped to the workspace. ErrRequestNotFound when
// the id matches no row in that workspace (a cross-tenant id is invisible).
func (s *AccessRequestService) GetRequest(ctx context.Context, workspaceID, requestID uuid.UUID) (*models.AccessRequest, error) {
	var req models.AccessRequest
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, requestID).
		Take(&req).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrRequestNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("lifecycle: load access_request: %w", err)
	}
	return &req, nil
}

// ListRequests returns the workspace's requests, newest first.
func (s *AccessRequestService) ListRequests(ctx context.Context, workspaceID uuid.UUID) ([]models.AccessRequest, error) {
	var out []models.AccessRequest
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ?", workspaceID).
		Order("created_at desc").
		Find(&out).Error; err != nil {
		return nil, fmt.Errorf("lifecycle: list access_requests: %w", err)
	}
	return out, nil
}

// History returns the ordered state-transition trail for a request (oldest
// first). It is workspace-scoped so a cross-tenant request id returns an empty
// trail rather than leaking another tenant's history.
func (s *AccessRequestService) History(ctx context.Context, workspaceID, requestID uuid.UUID) ([]models.AccessRequestStateHistory, error) {
	var out []models.AccessRequestStateHistory
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND request_id = ?", workspaceID, requestID).
		Order("created_at asc, id asc").
		Find(&out).Error; err != nil {
		return nil, fmt.Errorf("lifecycle: list state history: %w", err)
	}
	return out, nil
}

// ApproveRequest moves a request requested → approved.
func (s *AccessRequestService) ApproveRequest(ctx context.Context, workspaceID, requestID uuid.UUID, actor, reason string) error {
	return s.transitionRequest(ctx, workspaceID, requestID, StateApproved, actor, defaultReason(reason, "approved"))
}

// DenyRequest moves a request requested → denied (terminal).
func (s *AccessRequestService) DenyRequest(ctx context.Context, workspaceID, requestID uuid.UUID, actor, reason string) error {
	return s.transitionRequest(ctx, workspaceID, requestID, StateDenied, actor, defaultReason(reason, "denied"))
}

// CancelRequest moves a request requested|approved → cancelled (terminal). The
// requester or an admin can cancel before provisioning starts.
func (s *AccessRequestService) CancelRequest(ctx context.Context, workspaceID, requestID uuid.UUID, actor, reason string) error {
	return s.transitionRequest(ctx, workspaceID, requestID, StateCancelled, actor, defaultReason(reason, "cancelled"))
}

// transitionRequest opens its own transaction, loads the request (workspace
// scoped), gates the move through Transition, then writes the new state, the
// history row, and the audit event atomically.
func (s *AccessRequestService) transitionRequest(ctx context.Context, workspaceID, requestID uuid.UUID, to RequestState, actor, reason string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		_, err := s.TransitionInTx(ctx, tx, workspaceID, requestID, to, actor, reason)
		return err
	})
}

// TransitionInTx performs the read → Transition → write → history → audit
// sequence inside the supplied transaction and returns the updated request. It
// is exported so AccessProvisioningService can flip request state in the same
// transaction that inserts the access_grants row. The request is loaded with a
// workspace filter so a transition can never touch another tenant's row.
func (s *AccessRequestService) TransitionInTx(ctx context.Context, tx *gorm.DB, workspaceID, requestID uuid.UUID, to RequestState, actor, reason string) (*models.AccessRequest, error) {
	var req models.AccessRequest
	err := tx.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, requestID).
		Take(&req).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrRequestNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("lifecycle: load access_request for transition: %w", err)
	}

	from := req.State
	if err := Transition(from, to); err != nil {
		return nil, err
	}

	now := s.now()
	if err := tx.WithContext(ctx).
		Model(&models.AccessRequest{}).
		Where("workspace_id = ? AND id = ?", workspaceID, requestID).
		Updates(map[string]any{"state": to, "updated_at": now}).Error; err != nil {
		return nil, fmt.Errorf("lifecycle: update access_request state: %w", err)
	}
	req.State = to
	req.UpdatedAt = now

	hist := &models.AccessRequestStateHistory{
		WorkspaceID: workspaceID,
		RequestID:   requestID,
		FromState:   from,
		ToState:     to,
		Actor:       actor,
		Reason:      reason,
	}
	hist.CreatedAt = now
	hist.UpdatedAt = now
	if err := tx.WithContext(ctx).Create(hist).Error; err != nil {
		return nil, fmt.Errorf("lifecycle: insert state history: %w", err)
	}

	if err := appendAudit(ctx, tx, now, auditEntry{
		WorkspaceID: workspaceID,
		Actor:       actor,
		Action:      "access_request." + to,
		TargetRef:   requestID.String(),
	}); err != nil {
		return nil, err
	}
	return &req, nil
}

func defaultReason(reason, fallback string) string {
	if reason == "" {
		return fallback
	}
	return reason
}
