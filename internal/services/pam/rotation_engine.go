package pam

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
)

// RotationEngine performs a single target's credential rotation end-to-end: it
// resolves the protocol executor, reads the current sealed secret, asks the
// executor to change the upstream credential, then re-seals the new secret via
// the vault (which appends the tamper-evident audit event atomically). It also
// records a queryable RotationEvent and advances the policy's schedule/health.
//
// The engine is the single choke point shared by all three triggers — manual
// "rotate now", the interval scheduler, and rotate-on-checkin — so the safety
// and audit guarantees are identical regardless of what initiated the rotation.
type RotationEngine struct {
	db       *gorm.DB
	vault    *Vault
	registry *ExecutorRegistry
	now      func() time.Time
}

// NewRotationEngine wires an engine. registry defaults to the real executor set
// when nil so production callers get SSH/PostgreSQL/MySQL rotation out of the box.
func NewRotationEngine(db *gorm.DB, vault *Vault, registry *ExecutorRegistry) *RotationEngine {
	if registry == nil {
		registry = NewExecutorRegistry(10 * time.Second)
	}
	return &RotationEngine{db: db, vault: vault, registry: registry, now: time.Now}
}

// SetClock overrides the time source (tests).
func (e *RotationEngine) SetClock(now func() time.Time) {
	if now != nil {
		e.now = now
	}
}

// Registry exposes the executor registry (used to gate which protocols offer
// rotation in the API/UI).
func (e *RotationEngine) Registry() *ExecutorRegistry { return e.registry }

// RotateTarget rotates one target's credential under the given trigger and
// returns the recorded event. leaseID is set only for the checkin trigger.
//
// The flow is fail-safe: the executor leaves the upstream on the OLD credential
// on any error, and if the vault re-seal fails after a successful upstream
// change the engine rolls the upstream back so the vault and upstream can never
// disagree. Either way a RotationEvent is recorded and the policy health is
// updated.
func (e *RotationEngine) RotateTarget(ctx context.Context, workspaceID, targetID uuid.UUID, trigger, actor string, leaseID *uuid.UUID) (*models.RotationEvent, error) {
	if workspaceID == uuid.Nil || targetID == uuid.Nil {
		return nil, fmt.Errorf("%w: workspace_id and target_id are required", ErrValidation)
	}
	target, err := e.vault.GetTarget(ctx, workspaceID, targetID)
	if err != nil {
		return nil, err
	}
	policy, err := e.loadPolicy(ctx, workspaceID, targetID)
	if err != nil {
		return nil, err
	}

	executor, err := e.registry.For(target.Protocol)
	if err != nil {
		// An unsupported protocol is a PREFLIGHT failure, not an operational
		// one: nothing touched the upstream, and a protocol having no executor
		// is a permanent property of the target — not a transient fault that a
		// retry or an operator could clear. Return the error WITHOUT recording a
		// RotationEvent or touching policy health, exactly like the validation
		// guards above, so a manual "rotate now" against an unrotatable target
		// (the console already disables this) can't spam the history timeline or
		// falsely mark an otherwise-fine policy unhealthy. The scheduler never
		// reaches here because UpsertPolicy rejects interval/checkin policies on
		// unsupported protocols; the only caller is the manual API path.
		return nil, err
	}

	current, err := e.vault.OpenSecret(ctx, target)
	if err != nil {
		return e.fail(ctx, workspaceID, target, policy, trigger, actor, leaseID, fmt.Errorf("open current secret: %w", err))
	}

	next, err := executor.Rotate(ctx, target, current)
	if err != nil {
		// Upstream untouched (executor contract): nothing to roll back.
		return e.fail(ctx, workspaceID, target, policy, trigger, actor, leaseID, err)
	}

	if err := e.vault.RotateSecret(ctx, workspaceID, targetID, next, actor); err != nil {
		// The upstream already accepts `next` but we could not persist it. Roll
		// the upstream back to `current` so the still-sealed credential keeps
		// working; if the rollback itself fails we surface a loud error because
		// the vault and upstream are now genuinely out of sync.
		if rbErr := executor.Restore(ctx, target, next, current); rbErr != nil {
			logger.Errorf(ctx, "pam: rotation rollback FAILED for target %s: persist=%v rollback=%v", targetID, err, rbErr)
			return e.fail(ctx, workspaceID, target, policy, trigger, actor, leaseID,
				fmt.Errorf("persist rotated secret: %w; rollback also failed: %v", err, rbErr))
		}
		return e.fail(ctx, workspaceID, target, policy, trigger, actor, leaseID,
			fmt.Errorf("persist rotated secret (rolled back upstream): %w", err))
	}

	return e.succeed(ctx, workspaceID, target, policy, trigger, actor, leaseID)
}

// loadPolicy returns the target's rotation policy or nil when none exists.
func (e *RotationEngine) loadPolicy(ctx context.Context, workspaceID, targetID uuid.UUID) (*models.RotationPolicy, error) {
	var p models.RotationPolicy
	err := e.db.WithContext(ctx).
		Where("workspace_id = ? AND target_id = ?", workspaceID, targetID).
		Take(&p).Error
	switch {
	case err == nil:
		return &p, nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		return nil, nil
	default:
		return nil, fmt.Errorf("pam: load rotation policy: %w", err)
	}
}

// succeed records a successful rotation event and advances the policy.
func (e *RotationEngine) succeed(ctx context.Context, workspaceID uuid.UUID, target *models.PAMTarget, policy *models.RotationPolicy, trigger, actor string, leaseID *uuid.UUID) (*models.RotationEvent, error) {
	now := e.now().UTC()
	keyVersion := 0
	if t, err := e.vault.GetTarget(ctx, workspaceID, target.ID); err == nil {
		keyVersion = t.SecretKeyVersion
	}
	event := &models.RotationEvent{
		WorkspaceID: workspaceID,
		TargetID:    target.ID,
		Trigger:     trigger,
		Status:      models.RotationStatusSuccess,
		Protocol:    target.Protocol,
		Actor:       actor,
		LeaseID:     leaseID,
		KeyVersion:  keyVersion,
		Detail:      fmt.Sprintf("rotated %s credential", target.Protocol),
	}
	if policy != nil {
		event.PolicyID = &policy.ID
	}
	if err := e.writeOutcome(ctx, event, policy, now, ""); err != nil {
		return nil, err
	}
	return event, nil
}

// fail records a failed rotation event, advances the policy schedule (so a
// broken target retries next interval rather than every tick), and returns the
// triggering error so callers can surface it.
func (e *RotationEngine) fail(ctx context.Context, workspaceID uuid.UUID, target *models.PAMTarget, policy *models.RotationPolicy, trigger, actor string, leaseID *uuid.UUID, cause error) (*models.RotationEvent, error) {
	now := e.now().UTC()
	event := &models.RotationEvent{
		WorkspaceID: workspaceID,
		TargetID:    target.ID,
		Trigger:     trigger,
		Status:      models.RotationStatusFailed,
		Protocol:    target.Protocol,
		Actor:       actor,
		LeaseID:     leaseID,
		Error:       truncateError(cause.Error()),
	}
	if policy != nil {
		event.PolicyID = &policy.ID
	}
	if werr := e.writeOutcome(ctx, event, policy, now, truncateError(cause.Error())); werr != nil {
		logger.Errorf(ctx, "pam: record rotation failure for target %s: %v", target.ID, werr)
		// The outcome row was rolled back, so the event's BeforeCreate-assigned
		// ID points at nothing durable. Return a nil event (still with the
		// triggering cause) so a caller never hands a client an event it cannot
		// look up — the "rotate now" handler treats a nil event as a hard
		// failure and maps it to an HTTP error instead of a 200.
		return nil, cause
	}
	return event, cause
}

// writeOutcome persists the event row and (when present) updates the policy's
// health and interval schedule in a single transaction.
func (e *RotationEngine) writeOutcome(ctx context.Context, event *models.RotationEvent, policy *models.RotationPolicy, now time.Time, errText string) error {
	return e.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(event).Error; err != nil {
			return fmt.Errorf("pam: record rotation event: %w", err)
		}
		if policy == nil {
			return nil
		}
		updates := map[string]any{
			"last_status": event.Status,
			"last_error":  errText,
			"updated_at":  now,
		}
		if event.Status == models.RotationStatusSuccess {
			updates["last_rotation_at"] = now
		}
		// Advance the interval schedule on every attempt (success or failure) so
		// a failing target retries on the next interval instead of being
		// hammered every scheduler tick.
		if policy.IntervalRotationActive() {
			updates["next_rotation_at"] = now.Add(policy.Interval())
		}
		if err := tx.Model(&models.RotationPolicy{}).
			Where("id = ?", policy.ID).
			Updates(updates).Error; err != nil {
			return fmt.Errorf("pam: update rotation policy health: %w", err)
		}
		return nil
	})
}

// truncateError bounds an error string so a pathological upstream message can't
// bloat the events table.
func truncateError(s string) string {
	const max = 1024
	if len(s) > max {
		return s[:max]
	}
	return s
}
