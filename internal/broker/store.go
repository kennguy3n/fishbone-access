package broker

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
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
)

// Audit actions appended to the per-workspace hash chain for the agent
// lifecycle. They sit alongside the PAM actions (pam.target.create, ...) on the
// same chain so a tenant's tamper-evident trail covers brokered access too.
const (
	AuditActionAgentTokenMint = "agent.enroll.token"
	AuditActionAgentEnroll    = "agent.enroll"
	AuditActionAgentRevoke    = "agent.revoke"
	AuditActionBrokerOpen     = "agent.broker.open"
	AuditActionAgentOnline    = "agent.online"
	AuditActionAgentOffline   = "agent.offline"
	AuditActionAgentBind      = "agent.target.bind"
	AuditActionAgentUnbind    = "agent.target.unbind"
)

// ErrAgentUnavailable is returned when no online agent can serve a dial: either
// none is connected for the workspace or none advertises a path to the address.
// It is deliberately coarse so a caller (the gateway dialer) fails closed
// without leaking which agents exist.
var ErrAgentUnavailable = errors.New("broker: no agent available for target")

// RelayStore is the persistence the Relay needs: it authorizes a connecting
// agent against its issued certificate, records online/offline/heartbeat health
// transitions, and appends the broker-open audit event. It is an interface so
// the relay is unit-testable against an in-memory fake while production wires
// the GORM-backed store.
type RelayStore interface {
	AuthorizeConnect(ctx context.Context, id AgentIdentity) (*models.TargetAgent, error)
	OnRegister(ctx context.Context, workspaceID, agentID uuid.UUID, reg RegisterPayload) error
	OnHeartbeat(ctx context.Context, workspaceID, agentID uuid.UUID) error
	OnDisconnect(ctx context.Context, workspaceID, agentID uuid.UUID) error
	AuditBrokerOpen(ctx context.Context, workspaceID, agentID uuid.UUID, target, actor string) error
	// AuthorizeDial re-checks an agent is still live (not revoked, not deleted)
	// at session-open time, so a revoke that lands after the tunnel came up
	// still fails new sessions closed across the two processes.
	AuthorizeDial(ctx context.Context, workspaceID, agentID uuid.UUID) error
}

// GormStore is the GORM-backed RelayStore + enrollment persistence. Every query
// is explicitly scoped by workspace_id (the RLS backstop is permissive for this
// trusted cross-tenant relay process, exactly like the other background
// workers), and state transitions that matter to the audit trail append to the
// shared hash chain.
type GormStore struct {
	db  *gorm.DB
	now func() time.Time
}

// NewGormStore builds a GORM-backed store. now defaults to time.Now.
func NewGormStore(db *gorm.DB) *GormStore {
	return &GormStore{db: db, now: time.Now}
}

var _ RelayStore = (*GormStore)(nil)

// AuthorizeConnect fails closed unless the presented certificate maps to a live,
// non-revoked agent row whose persisted fingerprint matches and whose
// certificate has not expired. This is the row-level check layered on top of
// the TLS stack's CA verification.
func (s *GormStore) AuthorizeConnect(ctx context.Context, id AgentIdentity) (*models.TargetAgent, error) {
	var agent models.TargetAgent
	err := s.db.WithContext(ctx).
		Where("id = ? AND workspace_id = ?", id.AgentID, id.WorkspaceID).
		First(&agent).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("broker: agent not enrolled: %w", err)
		}
		return nil, err
	}
	if agent.Status == models.AgentStatusRevoked || agent.RevokedAt != nil {
		return nil, errors.New("broker: agent is revoked")
	}
	if agent.CertFingerprint != id.Fingerprint {
		return nil, errors.New("broker: certificate fingerprint does not match enrollment")
	}
	if !agent.CertNotAfter.IsZero() && s.now().After(agent.CertNotAfter) {
		return nil, errors.New("broker: agent certificate expired")
	}
	return &agent, nil
}

// OnRegister marks the agent online and replaces its self-reported reachable
// bindings with the freshly advertised set. Operator bindings are not stored
// here (they are derived from pam_targets.via_agent_id), so a registration only
// ever rewrites the agent's own advertised reach. The whole update is one
// transaction so a registration is atomic.
func (s *GormStore) OnRegister(ctx context.Context, workspaceID, agentID uuid.UUID, reg RegisterPayload) error {
	now := s.now()
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&models.TargetAgent{}).
			Where("id = ? AND workspace_id = ? AND status <> ?", agentID, workspaceID, models.AgentStatusRevoked).
			Updates(map[string]any{
				"status":        models.AgentStatusOnline,
				"last_seen_at":  now,
				"agent_version": reg.AgentVersion,
				"platform":      reg.Platform,
				"updated_at":    now,
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return errors.New("broker: agent not found or revoked")
		}
		// Replace the agent's self-reported reachable bindings.
		if err := tx.Where("workspace_id = ? AND agent_id = ?", workspaceID, agentID).
			Delete(&models.AgentReachableTarget{}).Error; err != nil {
			return err
		}
		for _, spec := range reg.Reachable {
			kind := spec.Kind
			if kind == "" {
				kind = ClassifyPattern(spec.Pattern)
			}
			row := &models.AgentReachableTarget{
				WorkspaceID: workspaceID,
				AgentID:     agentID,
				Pattern:     spec.Pattern,
				Kind:        kind,
			}
			if err := tx.Create(row).Error; err != nil {
				return err
			}
		}
		return lifecycle.AppendAuditTx(ctx, tx, now, lifecycle.AuditInput{
			WorkspaceID: workspaceID,
			Actor:       "agent:" + agentID.String(),
			Action:      AuditActionAgentOnline,
			TargetRef:   agentID.String(),
		})
	})
}

// OnHeartbeat refreshes last-seen and keeps the agent marked online.
func (s *GormStore) OnHeartbeat(ctx context.Context, workspaceID, agentID uuid.UUID) error {
	now := s.now()
	return s.db.WithContext(ctx).Model(&models.TargetAgent{}).
		Where("id = ? AND workspace_id = ? AND status <> ?", agentID, workspaceID, models.AgentStatusRevoked).
		Updates(map[string]any{"last_seen_at": now, "status": models.AgentStatusOnline, "updated_at": now}).Error
}

// OnDisconnect marks the agent offline (unless it was revoked) and appends an
// offline audit event.
func (s *GormStore) OnDisconnect(ctx context.Context, workspaceID, agentID uuid.UUID) error {
	now := s.now()
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&models.TargetAgent{}).
			Where("id = ? AND workspace_id = ? AND status <> ?", agentID, workspaceID, models.AgentStatusRevoked).
			Updates(map[string]any{"status": models.AgentStatusOffline, "updated_at": now})
		if res.Error != nil {
			return res.Error
		}
		return lifecycle.AppendAuditTx(ctx, tx, now, lifecycle.AuditInput{
			WorkspaceID: workspaceID,
			Actor:       "agent:" + agentID.String(),
			Action:      AuditActionAgentOffline,
			TargetRef:   agentID.String(),
		})
	})
}

// AuthorizeDial fails closed unless the agent row is still present and not
// revoked.
func (s *GormStore) AuthorizeDial(ctx context.Context, workspaceID, agentID uuid.UUID) error {
	var count int64
	if err := s.db.WithContext(ctx).Model(&models.TargetAgent{}).
		Where("id = ? AND workspace_id = ? AND status <> ?", agentID, workspaceID, models.AgentStatusRevoked).
		Count(&count).Error; err != nil {
		return err
	}
	if count == 0 {
		return ErrAgentUnavailable
	}
	return nil
}

// AuditBrokerOpen appends the broker-session-open event to the workspace chain.
func (s *GormStore) AuditBrokerOpen(ctx context.Context, workspaceID, agentID uuid.UUID, target, actor string) error {
	if actor == "" {
		actor = "pam-gateway"
	}
	return lifecycle.AppendAudit(ctx, s.db, s.now(), lifecycle.AuditInput{
		WorkspaceID: workspaceID,
		Actor:       actor,
		Action:      AuditActionBrokerOpen,
		TargetRef:   agentID.String(),
		Metadata:    auditMeta(map[string]any{"agent_id": agentID.String(), "target": target}),
	})
}

// auditMeta marshals v to datatypes.JSON, returning nil on the practically
// unreachable marshal error so an audit append never fails on metadata alone.
func auditMeta(v map[string]any) datatypes.JSON {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return datatypes.JSON(b)
}
