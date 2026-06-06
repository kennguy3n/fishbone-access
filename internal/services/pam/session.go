package pam

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
)

// ErrSessionNotFound is returned when a session does not exist in the workspace.
var ErrSessionNotFound = errors.New("pam: session not found")

// LiveController is the gateway-side capability the session manager uses to
// terminate a live connection when an admin kills an active session. The
// gateway's takeover hub implements it; defining the interface here keeps the
// dependency pointing gateway → pam (no import cycle). A nil controller means
// the manager records the DB-side termination but cannot sever an in-flight
// stream (best-effort).
type LiveController interface {
	// Terminate severs the live connection for sessionID if it is active in
	// this process, returning true when a live session was found and killed.
	Terminate(sessionID uuid.UUID) bool
}

// SessionManager owns the database lifecycle of a proxied session: it logs each
// command/statement with its policy decision into both the searchable
// pam_session_commands table and the tamper-evident workspace audit hash chain,
// and it closes or terminates sessions. It also sweeps expired connect-token
// leases.
type SessionManager struct {
	db         *gorm.DB
	evaluator  *CommandPolicyEvaluator
	controller LiveController
	now        func() time.Time
}

// NewSessionManager wires a manager. evaluator may be nil (commands are then
// always allowed but still logged); controller may be nil (terminate is
// DB-only, best-effort on the live stream).
func NewSessionManager(db *gorm.DB, evaluator *CommandPolicyEvaluator, controller LiveController) *SessionManager {
	return &SessionManager{db: db, evaluator: evaluator, controller: controller, now: time.Now}
}

// SetClock overrides the time source (tests).
func (m *SessionManager) SetClock(now func() time.Time) {
	if now != nil {
		m.now = now
	}
}

// LogCommand evaluates command against policy, persists a command row with the
// decision and the same decision into the audit chain, and returns the decision
// so the caller can enforce a deny (refuse to forward the command). Logging is
// best-effort relative to the gate: even a denied command is recorded.
func (m *SessionManager) LogCommand(ctx context.Context, session *models.PAMSession, command string) (Decision, error) {
	if session == nil {
		return Decision{}, fmt.Errorf("%w: session is required", ErrValidation)
	}
	decision := Decision{Effect: models.PAMDecisionAllow}
	if m.evaluator != nil {
		// On an evaluator error the decision is already the fail-closed deny the
		// evaluator returns, so the command is recorded as denied either way.
		decision, _ = m.evaluator.Evaluate(ctx, session.WorkspaceID, session.Subject, command)
	}

	now := m.now()
	err := m.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var maxSeq int64
		if err := tx.Model(&models.PAMSessionCommand{}).
			Where("session_id = ?", session.ID).
			Select("COALESCE(MAX(seq), 0)").
			Scan(&maxSeq).Error; err != nil {
			return fmt.Errorf("pam: read command seq: %w", err)
		}
		row := &models.PAMSessionCommand{
			WorkspaceID: session.WorkspaceID,
			SessionID:   session.ID,
			Seq:         maxSeq + 1,
			Command:     command,
			Decision:    decision.Effect,
			Reason:      decision.Reason,
		}
		row.CreatedAt = now
		row.UpdatedAt = now
		if err := tx.Create(row).Error; err != nil {
			return fmt.Errorf("pam: insert command: %w", err)
		}
		md, err := marshalMeta(map[string]any{
			"session_id": session.ID.String(),
			"seq":        row.Seq,
			"decision":   decision.Effect,
			"reason":     decision.Reason,
			"command":    command,
		})
		if err != nil {
			return err
		}
		return lifecycle.AppendAuditTx(ctx, tx, now, lifecycle.AuditInput{
			WorkspaceID: session.WorkspaceID,
			Actor:       session.Subject,
			Action:      "pam.command",
			TargetRef:   session.TargetID.String(),
			Metadata:    md,
		})
	})
	if err != nil {
		return Decision{}, err
	}
	return decision, nil
}

// CloseSession marks an active session closed (clean teardown) and stamps its
// end time. It is idempotent: closing an already-ended session is a no-op.
func (m *SessionManager) CloseSession(ctx context.Context, workspaceID, sessionID uuid.UUID) error {
	return m.endSession(ctx, workspaceID, sessionID, models.PAMSessionClosed, "", "pam.session.closed")
}

// TerminateSession kills an active session at an admin's request: it severs the
// live stream via the controller (if the session runs in this process), marks
// the row terminated with the admin actor, and records it in the audit chain.
func (m *SessionManager) TerminateSession(ctx context.Context, workspaceID, sessionID uuid.UUID, adminActor string) error {
	if adminActor == "" {
		return fmt.Errorf("%w: terminating admin is required", ErrValidation)
	}
	if m.controller != nil {
		m.controller.Terminate(sessionID)
	}
	return m.endSession(ctx, workspaceID, sessionID, models.PAMSessionTerminated, adminActor, "pam.session.terminated")
}

// endSession is the shared close/terminate path.
func (m *SessionManager) endSession(ctx context.Context, workspaceID, sessionID uuid.UUID, state, terminatedBy, action string) error {
	if workspaceID == uuid.Nil || sessionID == uuid.Nil {
		return fmt.Errorf("%w: workspace_id and session_id are required", ErrValidation)
	}
	now := m.now()
	var session models.PAMSession
	err := m.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, sessionID).
		Take(&session).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrSessionNotFound
	}
	if err != nil {
		return fmt.Errorf("pam: load session: %w", err)
	}
	if session.State != models.PAMSessionActive {
		return nil
	}

	updates := map[string]any{"state": state, "ended_at": now, "updated_at": now}
	if terminatedBy != "" {
		updates["terminated_by"] = terminatedBy
	}
	if err := m.db.WithContext(ctx).
		Model(&models.PAMSession{}).
		Where("workspace_id = ? AND id = ? AND state = ?", workspaceID, sessionID, models.PAMSessionActive).
		Updates(updates).Error; err != nil {
		return fmt.Errorf("pam: end session: %w", err)
	}

	actor := terminatedBy
	if actor == "" {
		actor = session.Subject
	}
	md, err := marshalMeta(map[string]any{
		"session_id": sessionID.String(),
		"state":      state,
	})
	if err != nil {
		return err
	}
	return lifecycle.AppendAudit(ctx, m.db, now, lifecycle.AuditInput{
		WorkspaceID: workspaceID,
		Actor:       actor,
		Action:      action,
		TargetRef:   session.TargetID.String(),
		Metadata:    md,
	})
}

// ExpireLeases flips a workspace's pending connect tokens whose lease window has
// closed to "expired". It is the leasing-expiry sweep a cron drives per
// workspace; it returns the number of tokens expired.
func (m *SessionManager) ExpireLeases(ctx context.Context, workspaceID uuid.UUID) (int64, error) {
	if workspaceID == uuid.Nil {
		return 0, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	now := m.now()
	res := m.db.WithContext(ctx).
		Model(&models.PAMConnectToken{}).
		Where("workspace_id = ? AND state = ? AND expires_at < ?", workspaceID, models.PAMConnectTokenPending, now).
		Updates(map[string]any{"state": models.PAMConnectTokenExpired, "updated_at": now})
	if res.Error != nil {
		return 0, fmt.Errorf("pam: expire leases: %w", res.Error)
	}
	return res.RowsAffected, nil
}
