package pam

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/aiclient"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
)

// ErrSessionNotFound is returned when a session does not exist in the workspace.
var ErrSessionNotFound = errors.New("pam: session not found")

// ErrSessionNotActive is returned when a control action (pause/resume) is
// attempted on a session that is no longer active. It is a state-machine
// conflict — the session exists but has already ended — so it maps to 409
// Conflict at the HTTP edge, mirroring ErrLeaseTerminal, rather than a 400 that
// would imply a malformed request.
var ErrSessionNotActive = errors.New("pam: session is not active")

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
	// Pause raises the operator→target soft-pause gate for sessionID if it is
	// active in this process, returning true when found. Reversible.
	Pause(sessionID uuid.UUID) bool
	// Resume lowers the soft-pause gate for sessionID if active in this
	// process, returning true when found.
	Resume(sessionID uuid.UUID) bool
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
	ai         *aiclient.AIClient
	now        func() time.Time
	// bg tracks in-flight detached post-session advisory scoring so a graceful
	// shutdown (Drain) can wait for those audit writes instead of dropping them.
	bg sync.WaitGroup
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

// SetRiskScorer attaches the AI client used to score a privileged session's
// command stream when it ends (advisory, fail-open). A nil client — or one that
// is not Configured() — leaves session-risk scoring off entirely, so a
// deployment without the agent pays no cost and emits no fallback noise.
func (m *SessionManager) SetRiskScorer(ai *aiclient.AIClient) {
	m.ai = ai
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
		// evaluator returns, so the command is recorded as denied either way. We
		// still surface the error at warn level: a deny caused by a policy-store
		// outage (rather than a real matching deny rule) is an operational signal
		// an operator needs to see, not silently swallow.
		var evalErr error
		decision, evalErr = m.evaluator.Evaluate(ctx, session.WorkspaceID, session.Subject, command)
		if evalErr != nil {
			logger.Warnf(ctx, "pam: command policy evaluation failed (fail-closed deny) for workspace %s subject %s: %v",
				session.WorkspaceID, session.Subject, evalErr)
		}
	}

	now := m.now()
	// The command seq is MAX(seq)+1 read inside the transaction. The
	// uq_pam_cmds_session_seq unique index guarantees no two rows share a
	// (workspace_id, session_id, seq), so if two writers on the same session
	// (e.g. concurrent SSH channels) read the same MAX(seq), one INSERT wins and
	// the other trips the constraint. We retry the loser on a fresh MAX(seq)
	// rather than letting a duplicate or a lost command through, preserving the
	// per-session monotonic-counter invariant.
	const maxSeqRetries = 5
	var err error
	for attempt := 0; attempt < maxSeqRetries; attempt++ {
		err = m.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			var maxSeq int64
			// Filter on workspace_id as well so the planner can use the leading
			// columns of uq_pam_cmds_session_seq (workspace_id, session_id, seq);
			// session_id alone is unique but does not let Postgres use the prefix.
			if err := tx.Model(&models.PAMSessionCommand{}).
				Where("workspace_id = ? AND session_id = ?", session.WorkspaceID, session.ID).
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
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			// Lost a seq race; recompute MAX(seq) and try again.
			continue
		}
		break
	}
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

// PauseSession records an operator-initiated soft-pause on an active session:
// it stamps the durable Paused flag (plus who/when) so the gateway reconciler
// holds the operator→target byte path even across processes, drives the
// in-process gate immediately when the session runs here (controller present),
// and appends a pam.session.paused audit event. It is idempotent — pausing an
// already-paused session re-affirms without a duplicate audit row — and only
// acts on active sessions.
func (m *SessionManager) PauseSession(ctx context.Context, workspaceID, sessionID uuid.UUID, adminActor string) error {
	return m.setPause(ctx, workspaceID, sessionID, adminActor, true)
}

// ResumeSession clears the soft-pause flag on an active session, lets operator
// input flow again (immediately when the session runs here), and audits
// pam.session.resumed. Idempotent and active-only.
func (m *SessionManager) ResumeSession(ctx context.Context, workspaceID, sessionID uuid.UUID, adminActor string) error {
	return m.setPause(ctx, workspaceID, sessionID, adminActor, false)
}

// setPause is the shared pause/resume path. The DB flag is the durable,
// cross-process intent; the controller call is the same-process fast path so a
// gateway-colocated manager need not wait for the reconciler poll.
func (m *SessionManager) setPause(ctx context.Context, workspaceID, sessionID uuid.UUID, adminActor string, paused bool) error {
	if workspaceID == uuid.Nil || sessionID == uuid.Nil {
		return fmt.Errorf("%w: workspace_id and session_id are required", ErrValidation)
	}
	if adminActor == "" {
		return fmt.Errorf("%w: pausing admin is required", ErrValidation)
	}
	now := m.now()
	action := "pam.session.paused"
	updates := map[string]any{"paused": paused, "updated_at": now}
	if paused {
		updates["paused_by"] = adminActor
		updates["paused_at"] = now
	} else {
		action = "pam.session.resumed"
		updates["paused_by"] = ""
		updates["paused_at"] = nil
	}

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
		return fmt.Errorf("%w (state %s)", ErrSessionNotActive, session.State)
	}

	md, err := marshalMeta(map[string]any{"session_id": sessionID.String(), "paused": paused})
	if err != nil {
		return err
	}
	// Flip the flag and audit atomically, gated on the flag actually changing
	// so a repeated pause/resume does not append a duplicate audit row.
	var changed bool
	if err := m.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&models.PAMSession{}).
			Where("workspace_id = ? AND id = ? AND state = ? AND paused = ?", workspaceID, sessionID, models.PAMSessionActive, !paused).
			Updates(updates)
		if res.Error != nil {
			return fmt.Errorf("pam: set session pause: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			return nil
		}
		changed = true
		return lifecycle.AppendAuditTx(ctx, tx, now, lifecycle.AuditInput{
			WorkspaceID: workspaceID,
			Actor:       adminActor,
			Action:      action,
			TargetRef:   session.TargetID.String(),
			Metadata:    md,
		})
	}); err != nil {
		return err
	}

	// Drive the in-process gate only on an actual transition. The hub's
	// Pause/Resume are idempotent, but skipping the no-op case avoids taking the
	// hub + recorder locks (and a pause-cond broadcast) when the durable flag
	// was already at the requested state.
	if changed && m.controller != nil {
		if paused {
			m.controller.Pause(sessionID)
		} else {
			m.controller.Resume(sessionID)
		}
	}
	return nil
}

// TerminateLeaseSessions tears down every active session bound to a lease when
// the lease leaves its live window (revoked or swept-expired). It satisfies the
// lease service's LeaseSessionTerminator contract: the credential stops being
// brokered the instant the lease dies. Best-effort per session — a failure on
// one is logged and the rest still proceed — but the method returns the first
// error so a caller can surface it. actor is "system" (the sweep/revoke path).
func (m *SessionManager) TerminateLeaseSessions(ctx context.Context, workspaceID, leaseID uuid.UUID, reason string) error {
	if workspaceID == uuid.Nil || leaseID == uuid.Nil {
		return fmt.Errorf("%w: workspace_id and lease_id are required", ErrValidation)
	}
	var sessions []models.PAMSession
	if err := m.db.WithContext(ctx).
		Select("id").
		Where("workspace_id = ? AND lease_id = ? AND state = ?", workspaceID, leaseID, models.PAMSessionActive).
		Find(&sessions).Error; err != nil {
		return fmt.Errorf("pam: list lease sessions: %w", err)
	}
	var firstErr error
	for _, s := range sessions {
		if err := m.TerminateSession(ctx, workspaceID, s.ID, "system"); err != nil {
			logger.Warnf(ctx, "pam: terminate session %s for %s lease %s: %v", s.ID, reason, leaseID, err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// GetSession loads one session scoped to its workspace.
func (m *SessionManager) GetSession(ctx context.Context, workspaceID, sessionID uuid.UUID) (*models.PAMSession, error) {
	if workspaceID == uuid.Nil || sessionID == uuid.Nil {
		return nil, fmt.Errorf("%w: workspace_id and session_id are required", ErrValidation)
	}
	var session models.PAMSession
	err := m.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, sessionID).
		Take(&session).Error
	switch {
	case err == nil:
		return &session, nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		return nil, ErrSessionNotFound
	default:
		return nil, fmt.Errorf("pam: load session: %w", err)
	}
}

// ListSessionsFilters narrows ListSessions for the session catalog.
type ListSessionsFilters struct {
	TargetID   uuid.UUID
	Subject    string
	ActiveOnly bool
	Limit      int
}

// ListSessions returns a workspace's proxied sessions newest-first for the
// session catalog and replay-retrieval UI. ActiveOnly restricts to live
// sessions.
func (m *SessionManager) ListSessions(ctx context.Context, workspaceID uuid.UUID, f ListSessionsFilters) ([]models.PAMSession, error) {
	if workspaceID == uuid.Nil {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	q := m.db.WithContext(ctx).Where("workspace_id = ?", workspaceID)
	if f.TargetID != uuid.Nil {
		q = q.Where("target_id = ?", f.TargetID)
	}
	if f.Subject != "" {
		q = q.Where("subject = ?", f.Subject)
	}
	if f.ActiveOnly {
		q = q.Where("state = ?", models.PAMSessionActive)
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var sessions []models.PAMSession
	if err := q.Order("started_at DESC").Limit(limit).Find(&sessions).Error; err != nil {
		return nil, fmt.Errorf("pam: list sessions: %w", err)
	}
	return sessions, nil
}

// SessionIntent is the durable control state the gateway reconciler applies to
// its in-process sessions: whether the session should still be live and whether
// it should be paused.
type SessionIntent struct {
	Active bool
	Paused bool
}

// SessionIntents returns the durable control intent for a set of session ids in
// a workspace, so the gateway reconciler can bridge cross-process pause/
// terminate decisions onto its in-process hub. Ids with no row are reported
// Active=false (terminate). This is the read half of the durable-intent channel
// the Paused flag and session State form between the control plane and the
// gateway.
func (m *SessionManager) SessionIntents(ctx context.Context, workspaceID uuid.UUID, sessionIDs []uuid.UUID) (map[uuid.UUID]SessionIntent, error) {
	out := make(map[uuid.UUID]SessionIntent, len(sessionIDs))
	if len(sessionIDs) == 0 {
		return out, nil
	}
	var rows []models.PAMSession
	if err := m.db.WithContext(ctx).
		Select("id", "state", "paused").
		Where("workspace_id = ? AND id IN ?", workspaceID, sessionIDs).
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("pam: load session intents: %w", err)
	}
	found := make(map[uuid.UUID]struct{}, len(rows))
	for _, r := range rows {
		out[r.ID] = SessionIntent{Active: r.State == models.PAMSessionActive, Paused: r.Paused}
		found[r.ID] = struct{}{}
	}
	// A session present in the hub but absent from the DB query (deleted or
	// wrong workspace) is treated as terminate-intent, never left dangling.
	for _, id := range sessionIDs {
		if _, ok := found[id]; !ok {
			out[id] = SessionIntent{Active: false}
		}
	}
	return out, nil
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

	// The conditional UPDATE and its audit append run in one transaction, and
	// the audit is gated on RowsAffected. If two callers race to end the same
	// session (e.g. the proxy's deferred close and an admin terminate arriving
	// together) both read state=active, but only the UPDATE that actually flips
	// the row affects a row; the loser sees 0 rows and skips the audit append,
	// so the chain gets exactly one end event instead of a duplicate.
	var ended bool
	if err := m.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&models.PAMSession{}).
			Where("workspace_id = ? AND id = ? AND state = ?", workspaceID, sessionID, models.PAMSessionActive).
			Updates(updates)
		if res.Error != nil {
			return fmt.Errorf("pam: end session: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			// Lost the race / already ended: nothing to audit.
			return nil
		}
		ended = true
		return lifecycle.AppendAuditTx(ctx, tx, now, lifecycle.AuditInput{
			WorkspaceID: workspaceID,
			Actor:       actor,
			Action:      action,
			TargetRef:   session.TargetID.String(),
			Metadata:    md,
		})
	}); err != nil {
		return err
	}

	// Post-session advisory risk scoring runs only on the writer that actually
	// ended the session (ended==true). It is dispatched to a detached background
	// goroutine so two AI round-trips (up to the client's per-call timeout each)
	// never add latency to the teardown hot path. It is fail-open and
	// best-effort: a scoring failure is logged inside the helper and never
	// propagates to the close result.
	if ended {
		m.scoreSessionAsync(ctx, &session)
	}
	return nil
}

// postSessionScoringTimeout is the outer ceiling on the detached advisory
// scoring that runs after a session closes. The two skills each carry their own
// per-call timeout in the AI client; this bound guarantees a wedged agent can
// never keep a background goroutine (and its DB handle) alive indefinitely.
const postSessionScoringTimeout = 45 * time.Second

// scoreSessionAsync dispatches the post-session advisory skills (risk scoring +
// behavioural analytics) to a detached background goroutine, so a slow or
// unreachable AI agent never blocks session teardown. The goroutine runs on a
// context detached from the caller's (the proxy connection is already gone) but
// retaining its values, bounded by postSessionScoringTimeout. It is a no-op
// without a configured agent. Drain waits for in-flight runs at shutdown.
func (m *SessionManager) scoreSessionAsync(ctx context.Context, session *models.PAMSession) {
	if m.ai == nil || !m.ai.Configured() {
		return
	}
	snapshot := *session
	detached := context.WithoutCancel(ctx)
	m.bg.Add(1)
	go func() {
		defer m.bg.Done()
		bgCtx, cancel := context.WithTimeout(detached, postSessionScoringTimeout)
		defer cancel()
		m.assessSessionRisk(bgCtx, &snapshot)
		m.analyzeBehaviour(bgCtx, &snapshot)
	}()
}

// Drain blocks until all in-flight detached post-session scoring goroutines
// have finished. The gateway calls it during graceful shutdown — after the
// listeners stop and before the database pool closes — so advisory audit writes
// are flushed rather than lost; tests use it to await the detached scoring
// deterministically.
func (m *SessionManager) Drain() {
	m.bg.Wait()
}

// sessionRiskMaxCommands bounds how many of a session's commands are fed to the
// PAM session-risk skill. A privileged session's transcript can be long; the
// most recent slice is enough signal for scoring and keeps the payload (and the
// agent round-trip) bounded.
const sessionRiskMaxCommands = 200

// assessSessionRisk scores a just-ended session's command stream through the
// pam_session_risk_assessment skill and records the verdict as a
// pam.session.risk_assessed audit event. It is advisory and fail-open: scoring
// is skipped entirely when no AI client is configured (no fallback noise on
// deployments without the agent), a degraded/agent-down result is dropped
// rather than recorded as a synthetic signal, and any persistence error is
// logged, never propagated — a session's clean teardown must not depend on the
// AI agent being reachable.
func (m *SessionManager) assessSessionRisk(ctx context.Context, session *models.PAMSession) {
	if m.ai == nil || !m.ai.Configured() {
		return
	}
	commands, err := m.recentCommands(ctx, session.WorkspaceID, session.ID, sessionRiskMaxCommands)
	if err != nil {
		logger.Warnf(ctx, "pam: session risk scoring: load commands for %s: %v", session.ID, err)
		return
	}
	risk := aiclient.AssessSessionRiskWithFallback(ctx, m.ai, m.resolveAITier(ctx, session.WorkspaceID), aiclient.SessionRiskInput{
		UserExternalID: session.Subject,
		TargetRef:      session.TargetID.String(),
		Commands:       commands,
		SourceIP:       session.ClientAddr,
	}, false)
	if risk.Degraded {
		// Agent unreachable: advisory absence of a signal, not a synthetic one.
		return
	}
	now := m.now()
	md, err := marshalMeta(map[string]any{
		"session_id":     session.ID.String(),
		"risk_score":     risk.Score,
		"risk_factors":   risk.Factors,
		"recommendation": risk.Recommendation,
	})
	if err != nil {
		logger.Warnf(ctx, "pam: session risk scoring: marshal metadata for %s: %v", session.ID, err)
		return
	}
	if err := m.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return lifecycle.AppendAuditTx(ctx, tx, now, lifecycle.AuditInput{
			WorkspaceID: session.WorkspaceID,
			Actor:       session.Subject,
			Action:      "pam.session.risk_assessed",
			TargetRef:   session.TargetID.String(),
			Metadata:    md,
		})
	}); err != nil {
		logger.Warnf(ctx, "pam: session risk scoring: append audit for %s: %v", session.ID, err)
	}
}

// behaviourMaxSessions bounds how many of a user's recent privileged sessions
// feed the behavioural-analytics skill: enough history to establish a baseline
// without an unbounded scan as a long-tenured user's session count grows.
const behaviourMaxSessions = 50

// analyzeBehaviour runs post-session behavioural analytics for the session's
// user (advisory, fail-open). Like assessSessionRisk it is a no-op without a
// configured agent, and any error is logged rather than propagated to the close.
func (m *SessionManager) analyzeBehaviour(ctx context.Context, session *models.PAMSession) {
	if m.ai == nil || !m.ai.Configured() {
		return
	}
	if _, err := m.AnalyzeUserBehaviour(ctx, session.WorkspaceID, session.Subject); err != nil {
		logger.Warnf(ctx, "pam: behavioural analytics for %s: %v", session.Subject, err)
	}
}

// AnalyzeUserBehaviour scores a user's recent privileged sessions through the
// pam_behavioural_analytics skill and records each returned anomaly as a
// pam.session.behaviour_anomaly audit event, returning the anomalies. It builds
// the skill's baseline (the user's habitual targets and average command volume)
// from the same recent-session window. It is advisory and fail-open: with no
// configured agent it is a no-op, an agent outage yields no anomalies (the
// absence of a signal, not a synthetic one), and a per-anomaly persistence error
// is logged without aborting the rest. Exported so a periodic per-user job can
// drive it in addition to the post-session hook.
func (m *SessionManager) AnalyzeUserBehaviour(ctx context.Context, workspaceID uuid.UUID, userExternalID string) ([]aiclient.AnomalyEvent, error) {
	if m.ai == nil || !m.ai.Configured() {
		return nil, nil
	}
	if workspaceID == uuid.Nil || userExternalID == "" {
		return nil, fmt.Errorf("%w: workspace_id and user are required", ErrValidation)
	}
	var sessions []models.PAMSession
	if err := m.db.WithContext(ctx).
		Where("workspace_id = ? AND subject = ? AND ended_at IS NOT NULL", workspaceID, userExternalID).
		Order("started_at desc").
		Limit(behaviourMaxSessions).
		Find(&sessions).Error; err != nil {
		return nil, fmt.Errorf("pam: load user sessions: %w", err)
	}
	if len(sessions) == 0 {
		return nil, nil
	}

	ids := make([]uuid.UUID, len(sessions))
	for i, s := range sessions {
		ids[i] = s.ID
	}
	type sessionCount struct {
		SessionID uuid.UUID
		N         int
	}
	var counts []sessionCount
	if err := m.db.WithContext(ctx).
		Model(&models.PAMSessionCommand{}).
		Select("session_id, count(*) as n").
		Where("workspace_id = ? AND session_id IN ?", workspaceID, ids).
		Group("session_id").
		Scan(&counts).Error; err != nil {
		return nil, fmt.Errorf("pam: count session commands: %w", err)
	}
	countByID := make(map[uuid.UUID]int, len(counts))
	for _, c := range counts {
		countByID[c.SessionID] = c.N
	}

	behaviourSessions := make([]aiclient.BehaviourSession, 0, len(sessions))
	targetSet := make(map[string]struct{}, len(sessions))
	totalCommands := 0
	for _, s := range sessions {
		duration := 0
		if s.EndedAt != nil {
			duration = int(s.EndedAt.Sub(s.StartedAt).Minutes())
		}
		n := countByID[s.ID]
		totalCommands += n
		target := s.TargetID.String()
		targetSet[target] = struct{}{}
		behaviourSessions = append(behaviourSessions, aiclient.BehaviourSession{
			StartHour:    s.StartedAt.Hour(),
			DurationMin:  duration,
			CommandCount: n,
			Target:       target,
		})
	}
	targets := make([]string, 0, len(targetSet))
	for target := range targetSet {
		targets = append(targets, target)
	}
	sort.Strings(targets)

	anomalies := aiclient.AnalyzeBehaviourWithFallback(ctx, m.ai, m.resolveAITier(ctx, workspaceID), aiclient.BehaviourAnalyticsInput{
		UserExternalID: userExternalID,
		Sessions:       behaviourSessions,
		Baseline: &aiclient.BehaviourBaseline{
			Targets:         targets,
			AvgCommandCount: float64(totalCommands) / float64(len(sessions)),
		},
	})
	if len(anomalies) == 0 {
		return nil, nil
	}

	now := m.now()
	for _, anomaly := range anomalies {
		md, err := marshalMeta(map[string]any{
			"user_external_id": userExternalID,
			"kind":             anomaly.Kind,
			"severity":         anomaly.Severity,
			"reason":           anomaly.Reason,
			"confidence":       anomaly.Confidence,
		})
		if err != nil {
			logger.Warnf(ctx, "pam: behavioural anomaly: marshal metadata for %s: %v", userExternalID, err)
			continue
		}
		if err := m.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			return lifecycle.AppendAuditTx(ctx, tx, now, lifecycle.AuditInput{
				WorkspaceID: workspaceID,
				Actor:       userExternalID,
				Action:      "pam.session.behaviour_anomaly",
				TargetRef:   anomaly.Kind,
				Metadata:    md,
			})
		}); err != nil {
			logger.Warnf(ctx, "pam: behavioural anomaly: append audit for %s: %v", userExternalID, err)
		}
	}
	return anomalies, nil
}

// recentCommands loads up to limit of a session's logged commands for risk
// scoring, returning them in transcript (ascending seq) order. When a session's
// transcript is longer than limit it is the MOST RECENT commands that matter, so
// the query selects the tail (Order seq DESC + Limit) and the slice is reversed
// back to ascending order for the scorer. Denied commands are included — an
// attempt that policy blocked is itself a risk signal.
func (m *SessionManager) recentCommands(ctx context.Context, workspaceID, sessionID uuid.UUID, limit int) ([]string, error) {
	var commands []string
	if err := m.db.WithContext(ctx).
		Model(&models.PAMSessionCommand{}).
		Where("workspace_id = ? AND session_id = ?", workspaceID, sessionID).
		Order("seq DESC").
		Limit(limit).
		Pluck("command", &commands).Error; err != nil {
		return nil, fmt.Errorf("pam: load session commands: %w", err)
	}
	for i, j := 0, len(commands)-1; i < j; i, j = i+1, j-1 {
		commands[i], commands[j] = commands[j], commands[i]
	}
	return commands, nil
}

// resolveAITier maps the session's workspace plan to the AI agent tier, matching
// the lifecycle risk-review resolver: pro → local_4b, ultimate → local_8b,
// everything else (and any lookup error) → deterministic, so a plan lookup
// failure degrades to the cheapest tier rather than blocking scoring.
func (m *SessionManager) resolveAITier(ctx context.Context, workspaceID uuid.UUID) string {
	var ws models.Workspace
	if err := m.db.WithContext(ctx).
		Select("plan").
		Where("id = ?", workspaceID).
		Take(&ws).Error; err != nil {
		return "deterministic"
	}
	switch strings.TrimSpace(strings.ToLower(ws.Plan)) {
	case "pro":
		return "local_4b"
	case "ultimate":
		return "local_8b"
	default:
		return "deterministic"
	}
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
