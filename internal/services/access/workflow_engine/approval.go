package workflow_engine

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
)

// Approval decision values persisted in workflow_approvals.decision.
const (
	ApprovalDecisionApprove = "approve"
	ApprovalDecisionDeny    = "deny"
)

// Required approver counts per workflow lane. manager_approval needs a single
// approver; security_review needs two DISTINCT approvers (four-eyes) before a
// high-risk or sensitive request is released.
const (
	approvalsManagerLane  = 1
	approvalsSecurityLane = 2
)

// RequiredApprovals returns how many distinct approve decisions a request in the
// given lane needs before it can transition requested → approved. The
// auto_approve lane needs none (the workflow service already approved it); an
// unknown lane is treated as manager_approval (fail-safe: require a human).
func RequiredApprovals(stepType string) int {
	switch stepType {
	case lifecycle.WorkflowStepAutoApprove:
		return 0
	case lifecycle.WorkflowStepSecurityReview:
		return approvalsSecurityLane
	case lifecycle.WorkflowStepManagerApproval:
		return approvalsManagerLane
	default:
		return approvalsManagerLane
	}
}

// ChainState summarizes an approval chain's progress, derived purely from the
// persisted decisions so it is correct after a worker restart.
type ChainState struct {
	// Required is the number of distinct approvals the lane needs.
	Required int
	// Approvals is the number of distinct approvers who approved.
	Approvals int
	// Rejected is true when at least one approver denied — a single deny
	// rejects the request regardless of how many approvals exist.
	Rejected bool
}

// Satisfied reports whether the chain is complete: no deny and enough distinct
// approvals.
func (c ChainState) Satisfied() bool {
	return !c.Rejected && c.Approvals >= c.Required
}

// Remaining is the number of further approvals needed (0 once satisfied or
// rejected).
func (c ChainState) Remaining() int {
	if c.Rejected || c.Approvals >= c.Required {
		return 0
	}
	return c.Required - c.Approvals
}

// ApprovalStore persists and evaluates approval-chain decisions over the
// workflow_approvals table. All methods are workspace-scoped for tenant
// isolation.
type ApprovalStore struct {
	db *gorm.DB
}

// NewApprovalStore builds a store over the given GORM handle.
func NewApprovalStore(db *gorm.DB) *ApprovalStore {
	return &ApprovalStore{db: db}
}

// WithinTx runs fn inside a single database transaction over the store's handle.
// The engine uses it to make "record a decision AND transition the request"
// atomic: fn first locks the request row, then calls RecordTx/StateTx and the
// lifecycle transition on the same tx, so a concurrent Approve/Deny on the same
// request cannot interleave between the chain read and the state write.
func (s *ApprovalStore) WithinTx(ctx context.Context, fn func(tx *gorm.DB) error) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("workflow_engine: ApprovalStore not initialised")
	}
	return s.db.WithContext(ctx).Transaction(fn)
}

// Record upserts one approver's decision on a request in its own transaction.
// See RecordTx for the idempotency contract.
func (s *ApprovalStore) Record(ctx context.Context, workspaceID, requestID uuid.UUID, approver, approverRole, decision, reason string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("workflow_engine: ApprovalStore not initialised")
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return s.RecordTx(ctx, tx, workspaceID, requestID, approver, approverRole, decision, reason)
	})
}

// RecordTx upserts one approver's decision on a request using the supplied
// transaction. It is idempotent per approver: a re-submitted decision updates
// that approver's row (via the uq_workflow_approval unique index) rather than
// inflating the chain, so a retried API call or a redelivered job cannot let one
// approver count twice. Callers that need atomicity with the request-state
// transition pass the same tx that holds the request row lock.
func (s *ApprovalStore) RecordTx(ctx context.Context, tx *gorm.DB, workspaceID, requestID uuid.UUID, approver, approverRole, decision, reason string) error {
	if tx == nil {
		return fmt.Errorf("workflow_engine: RecordTx: tx is required")
	}
	if workspaceID == uuid.Nil || requestID == uuid.Nil {
		return fmt.Errorf("workflow_engine: Record: workspace_id and request_id are required")
	}
	approver = strings.TrimSpace(approver)
	if approver == "" {
		return fmt.Errorf("workflow_engine: Record: approver is required")
	}
	switch decision {
	case ApprovalDecisionApprove, ApprovalDecisionDeny:
	default:
		return fmt.Errorf("workflow_engine: Record: unknown decision %q", decision)
	}

	// Upsert keyed on (workspace_id, request_id, approver). A select-then-
	// insert/update (rather than ON CONFLICT) keeps the idempotency invariant
	// portably: the uq_workflow_approval index is partial (WHERE deleted_at IS
	// NULL), and a bare ON CONFLICT column list does not match a partial index on
	// SQLite. Running on the caller's tx lets the decision write share the
	// request row lock the engine already holds.
	var existing models.WorkflowApproval
	err := tx.WithContext(ctx).Where("workspace_id = ? AND request_id = ? AND approver = ?", workspaceID, requestID, approver).
		First(&existing).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		row := models.WorkflowApproval{
			WorkspaceID:  workspaceID,
			RequestID:    requestID,
			Approver:     approver,
			ApproverRole: approverRole,
			Decision:     decision,
			Reason:       reason,
		}
		if err := tx.WithContext(ctx).Create(&row).Error; err != nil {
			return fmt.Errorf("workflow_engine: record approval: %w", err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("workflow_engine: load approval for update: %w", err)
	default:
		existing.Decision = decision
		existing.ApproverRole = approverRole
		existing.Reason = reason
		if err := tx.WithContext(ctx).Save(&existing).Error; err != nil {
			return fmt.Errorf("workflow_engine: update approval: %w", err)
		}
		return nil
	}
}

// Decisions returns every recorded decision for a request (workspace-scoped).
func (s *ApprovalStore) Decisions(ctx context.Context, workspaceID, requestID uuid.UUID) ([]models.WorkflowApproval, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("workflow_engine: ApprovalStore not initialised")
	}
	return s.decisions(s.db.WithContext(ctx), workspaceID, requestID)
}

// decisions lists a request's decisions over the supplied handle (the store's
// db or a caller's tx).
func (s *ApprovalStore) decisions(db *gorm.DB, workspaceID, requestID uuid.UUID) ([]models.WorkflowApproval, error) {
	var out []models.WorkflowApproval
	if err := db.
		Where("workspace_id = ? AND request_id = ?", workspaceID, requestID).
		Order("created_at asc, id asc").
		Find(&out).Error; err != nil {
		return nil, fmt.Errorf("workflow_engine: list approvals: %w", err)
	}
	return out, nil
}

// State derives the chain state for a request given the lane's required count.
func (s *ApprovalStore) State(ctx context.Context, workspaceID, requestID uuid.UUID, required int) (ChainState, error) {
	if s == nil || s.db == nil {
		return ChainState{}, fmt.Errorf("workflow_engine: ApprovalStore not initialised")
	}
	return s.StateTx(ctx, s.db.WithContext(ctx), workspaceID, requestID, required)
}

// StateTx derives the chain state over the supplied transaction so the engine
// can re-evaluate the chain on the same tx (and request row lock) under which it
// just recorded a decision. It counts DISTINCT approvers (the unique index
// already guarantees one row per approver, but counting distinct is defensive)
// and flags any deny.
func (s *ApprovalStore) StateTx(ctx context.Context, tx *gorm.DB, workspaceID, requestID uuid.UUID, required int) (ChainState, error) {
	if tx == nil {
		return ChainState{}, fmt.Errorf("workflow_engine: StateTx: tx is required")
	}
	decisions, err := s.decisions(tx.WithContext(ctx), workspaceID, requestID)
	if err != nil {
		return ChainState{}, err
	}
	st := ChainState{Required: required}
	seen := make(map[string]struct{}, len(decisions))
	for _, d := range decisions {
		if d.Decision == ApprovalDecisionDeny {
			st.Rejected = true
		}
		if d.Decision == ApprovalDecisionApprove {
			if _, dup := seen[d.Approver]; !dup {
				seen[d.Approver] = struct{}{}
				st.Approvals++
			}
		}
	}
	return st, nil
}
