package broker

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

// HealthOfflineAfter is how long after an agent's last heartbeat the control
// plane treats it as stale: a generous multiple of the agent heartbeat so a
// single missed beat (or a brief network blip) does not flap an agent to
// "offline". The directory derives liveness from the persisted last_seen_at —
// the cross-process signal between the relay (which writes heartbeats) and the
// API (which reads them) — rather than the relay's in-memory connection table,
// which a different binary cannot observe.
const HealthOfflineAfter = 90 * time.Second

// AgentHealth is the derived liveness of an agent for the management surface.
type AgentHealth string

const (
	AgentHealthOnline  AgentHealth = "online"
	AgentHealthStale   AgentHealth = "stale"
	AgentHealthOffline AgentHealth = "offline"
	AgentHealthRevoked AgentHealth = "revoked"
)

// AgentView is an agent enriched with its derived health for the API/UI.
type AgentView struct {
	Agent  models.TargetAgent `json:"agent"`
	Health AgentHealth        `json:"health"`
}

// AgentDirectory is the read/bind side of the agent feature used by the HTTP
// handlers: it lists agents with derived health, exposes the reachable specs an
// agent advertises, and binds/unbinds PAM targets to an agent (the operator
// decision that flips a target to "reach via agent"). Every query is explicitly
// workspace-scoped, and every binding change appends to the audit chain.
type AgentDirectory struct {
	db  *gorm.DB
	now func() time.Time
}

// NewAgentDirectory builds the directory.
func NewAgentDirectory(db *gorm.DB) *AgentDirectory {
	return &AgentDirectory{db: db, now: time.Now}
}

// SetClock overrides the time source (tests).
func (d *AgentDirectory) SetClock(now func() time.Time) {
	if now != nil {
		d.now = now
	}
}

// ListAgents returns the workspace's agents (newest first) with derived health.
func (d *AgentDirectory) ListAgents(ctx context.Context, workspaceID uuid.UUID) ([]AgentView, error) {
	var agents []models.TargetAgent
	if err := d.db.WithContext(ctx).
		Where("workspace_id = ?", workspaceID).
		Order("created_at DESC").
		Find(&agents).Error; err != nil {
		return nil, err
	}
	views := make([]AgentView, 0, len(agents))
	for i := range agents {
		views = append(views, AgentView{Agent: agents[i], Health: d.health(agents[i])})
	}
	return views, nil
}

// GetAgent returns one agent with derived health.
func (d *AgentDirectory) GetAgent(ctx context.Context, workspaceID, agentID uuid.UUID) (*AgentView, error) {
	var agent models.TargetAgent
	if err := d.db.WithContext(ctx).
		Where("id = ? AND workspace_id = ?", agentID, workspaceID).
		First(&agent).Error; err != nil {
		return nil, err
	}
	return &AgentView{Agent: agent, Health: d.health(agent)}, nil
}

// Reachable returns the reachable specs (self-reported and operator-created)
// advertised for an agent.
func (d *AgentDirectory) Reachable(ctx context.Context, workspaceID, agentID uuid.UUID) ([]models.AgentReachableTarget, error) {
	var rows []models.AgentReachableTarget
	if err := d.db.WithContext(ctx).
		Where("workspace_id = ? AND agent_id = ?", workspaceID, agentID).
		Order("created_at ASC").
		Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// BoundTargets returns the PAM targets currently routed through this agent.
func (d *AgentDirectory) BoundTargets(ctx context.Context, workspaceID, agentID uuid.UUID) ([]models.PAMTarget, error) {
	var rows []models.PAMTarget
	if err := d.db.WithContext(ctx).
		Where("workspace_id = ? AND via_agent_id = ?", workspaceID, agentID).
		Order("name ASC").
		Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// BindTarget routes a PAM target through an agent (sets via_agent_id) after
// verifying both the target and the agent belong to the workspace and the agent
// is not revoked — fail-closed so a target can never be bound to another
// tenant's agent. Appends an audit event in the same transaction.
func (d *AgentDirectory) BindTarget(ctx context.Context, workspaceID, agentID, targetID uuid.UUID, actor string) error {
	if workspaceID == uuid.Nil || agentID == uuid.Nil || targetID == uuid.Nil {
		return fmt.Errorf("%w: workspace_id, agent_id and target_id are required", ErrValidation)
	}
	now := d.now()
	return d.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var agent models.TargetAgent
		if err := tx.Where("id = ? AND workspace_id = ?", agentID, workspaceID).First(&agent).Error; err != nil {
			return err
		}
		if agent.Status == models.AgentStatusRevoked {
			return fmt.Errorf("%w: agent is revoked", ErrValidation)
		}
		res := tx.Model(&models.PAMTarget{}).
			Where("id = ? AND workspace_id = ?", targetID, workspaceID).
			Update("via_agent_id", agentID)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}
		return lifecycle.AppendAuditTx(ctx, tx, now, lifecycle.AuditInput{
			WorkspaceID: workspaceID,
			Actor:       actor,
			Action:      AuditActionAgentBind,
			TargetRef:   targetID.String(),
			Metadata:    auditMeta(map[string]any{"agent_id": agentID.String()}),
		})
	})
}

// UnbindTarget reverts a PAM target to direct dialing (clears via_agent_id).
func (d *AgentDirectory) UnbindTarget(ctx context.Context, workspaceID, targetID uuid.UUID, actor string) error {
	if workspaceID == uuid.Nil || targetID == uuid.Nil {
		return fmt.Errorf("%w: workspace_id and target_id are required", ErrValidation)
	}
	now := d.now()
	return d.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&models.PAMTarget{}).
			Where("id = ? AND workspace_id = ?", targetID, workspaceID).
			Update("via_agent_id", gorm.Expr("NULL"))
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}
		return lifecycle.AppendAuditTx(ctx, tx, now, lifecycle.AuditInput{
			WorkspaceID: workspaceID,
			Actor:       actor,
			Action:      AuditActionAgentUnbind,
			TargetRef:   targetID.String(),
		})
	})
}

// health derives an agent's liveness from its persisted status, last-seen, and
// certificate validity.
func (d *AgentDirectory) health(a models.TargetAgent) AgentHealth {
	if a.Status == models.AgentStatusRevoked || a.RevokedAt != nil {
		return AgentHealthRevoked
	}
	if a.LastSeenAt == nil {
		return AgentHealthOffline
	}
	if a.Status == models.AgentStatusOffline {
		return AgentHealthOffline
	}
	if d.now().Sub(*a.LastSeenAt) > HealthOfflineAfter {
		return AgentHealthStale
	}
	if a.Status == models.AgentStatusOnline {
		return AgentHealthOnline
	}
	return AgentHealthOffline
}

// IsNotFound reports whether err is a record-not-found, so handlers can map it
// to a 404 without importing gorm.
func IsNotFound(err error) bool { return errors.Is(err, gorm.ErrRecordNotFound) }
