package broker

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// The session directory is the durable, cross-replica record of WHICH replica
// owns each agent's live tunnel. It closes the multi-replica HA gap: an agent's
// mTLS tunnel terminates on exactly one pam-gateway replica (its yamux session
// lives only in that replica's memory), but a privileged session-open that
// needs DialThroughAgent may be served by a DIFFERENT replica. Before this, the
// dial failed closed even though the agent was online elsewhere; with the
// directory, the serving replica looks up the owner and forwards the dial to it
// (see forwarder.go).
//
// Ownership model — single-writer per (workspace_id, agent_id), epoch-CAS:
//   - Claim() on register: takes (or takes over) ownership, bumping epoch. The
//     claiming replica remembers the returned epoch on its agentConn.
//   - Refresh() on heartbeat: COALESCED last-seen bump, conditioned on the
//     caller still holding its claimed (node, epoch). A failed CAS means another
//     replica took over (the agent reconnected elsewhere) — the stale tunnel is
//     dropped.
//   - Release() on disconnect: clears the row, conditioned on (node, epoch), so
//     a late release from a crashed-then-superseded owner cannot delete a newer
//     owner's claim.
//
// Postgres is the source of truth (RLS-scoped, migration 0080). An optional
// Redis fast-path (redis_directory.go) sits in FRONT of it as a write-through
// cache; it never becomes authoritative and always fails open to Postgres.

// ErrOwnershipLost is returned by Refresh when the caller no longer holds the
// (node, epoch) it claimed — another replica took over ownership (the agent
// reconnected elsewhere). The caller drops its now-stale tunnel.
var ErrOwnershipLost = errors.New("broker: session-directory ownership lost (superseded by another replica)")

// OwnerEntry is a directory lookup result: the replica that currently owns an
// agent's tunnel and the internal address other replicas dial to reach it.
type OwnerEntry struct {
	NodeID      string
	ForwardAddr string
	Epoch       int64
	LastSeenAt  time.Time
}

// SessionDirectory is the cross-replica ownership registry the Relay consults
// when an agent is not in its local tunnel map. It is an interface so the Relay
// is unit-testable against an in-memory fake, the production path wires the
// GORM-backed store, and the optional Redis fast-path decorates it transparently
// (all three satisfy the same contract).
type SessionDirectory interface {
	// Claim records this node as the owner of the agent's tunnel, taking over
	// any previous owner, and returns the new ownership epoch. Called on
	// register (coalesced — never per-dial).
	Claim(ctx context.Context, workspaceID, agentID uuid.UUID, nodeID, forwardAddr string) (epoch int64, err error)
	// Refresh bumps last-seen for an ownership the caller still holds. It returns
	// ErrOwnershipLost if (node, epoch) no longer matches the stored owner.
	Refresh(ctx context.Context, workspaceID, agentID uuid.UUID, nodeID string, epoch int64) error
	// Release clears the ownership row iff the caller still holds (node, epoch).
	// A no-longer-owned row is left untouched (idempotent, never an error).
	Release(ctx context.Context, workspaceID, agentID uuid.UUID, nodeID string, epoch int64) error
	// Lookup returns the current owner of an agent's tunnel and whether that
	// entry is fresh (last-seen within the staleness window). A missing row
	// returns (nil, false, nil).
	Lookup(ctx context.Context, workspaceID, agentID uuid.UUID) (entry *OwnerEntry, fresh bool, err error)
	// OnlineCount reports how many agents in a workspace have a FRESH owner
	// anywhere in the fleet (global online state, not just this replica).
	OnlineCount(ctx context.Context, workspaceID uuid.UUID) (int, error)
	// IsOnline reports whether a specific agent has a fresh owner anywhere.
	IsOnline(ctx context.Context, workspaceID, agentID uuid.UUID) (bool, error)
}

// GormSessionDirectory is the Postgres-backed (SQLite in tests) SessionDirectory
// — the authoritative source of truth. Every query is explicitly workspace
// scoped, exactly like GormStore: the relay is a trusted cross-tenant process,
// so the RLS backstop (migration 0080) is permissive for it while the explicit
// scoping enforces isolation in the query itself.
type GormSessionDirectory struct {
	db         *gorm.DB
	now        func() time.Time
	staleAfter time.Duration
}

var _ SessionDirectory = (*GormSessionDirectory)(nil)

// NewGormSessionDirectory builds the GORM-backed directory. staleAfter bounds
// how long after a missed heartbeat an owner is treated as crashed (a forwarded
// dial against a stale owner fails closed); non-positive uses HealthOfflineAfter
// so the directory and the management health surface agree on "online".
func NewGormSessionDirectory(db *gorm.DB, staleAfter time.Duration) *GormSessionDirectory {
	if staleAfter <= 0 {
		staleAfter = HealthOfflineAfter
	}
	return &GormSessionDirectory{db: db, now: time.Now, staleAfter: staleAfter}
}

// SetClock overrides the time source (tests).
func (d *GormSessionDirectory) SetClock(now func() time.Time) {
	if now != nil {
		d.now = now
	}
}

// Claim takes (or takes over) ownership atomically and returns the new epoch.
//
// It is an upsert that bumps the epoch on conflict, followed by a read of the
// resulting epoch in the SAME transaction. This is portable (no RETURNING, no
// SELECT ... FOR UPDATE) and gives the desired takeover semantics under a race:
// concurrent claims serialize on the row, each increments the epoch, and the
// LATER claim ends up with the higher epoch — so the earlier owner's next
// Refresh/Release CAS-fails and it yields, exactly as a reconnect-elsewhere
// should behave.
func (d *GormSessionDirectory) Claim(ctx context.Context, workspaceID, agentID uuid.UUID, nodeID, forwardAddr string) (int64, error) {
	now := d.now()
	var epoch int64
	err := d.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		entry := models.AgentSessionDirectoryEntry{
			WorkspaceID:      workspaceID,
			AgentID:          agentID,
			OwnerNodeID:      nodeID,
			OwnerForwardAddr: forwardAddr,
			Epoch:            1,
			LastSeenAt:       now,
			CreatedAt:        now,
			UpdatedAt:        now,
		}
		// On conflict (the agent already has an owner), take over: point the row
		// at this node and bump the generation. The bare `epoch` on the right of
		// the assignment refers to the EXISTING row value in both Postgres and
		// SQLite ON CONFLICT DO UPDATE, so this is existing+1.
		if err := tx.Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "workspace_id"}, {Name: "agent_id"}},
			DoUpdates: clause.Assignments(map[string]any{
				"owner_node_id":      nodeID,
				"owner_forward_addr": forwardAddr,
				"epoch":              gorm.Expr("agent_session_directory.epoch + 1"),
				"last_seen_at":       now,
				"updated_at":         now,
			}),
		}).Create(&entry).Error; err != nil {
			return err
		}
		var stored models.AgentSessionDirectoryEntry
		if err := tx.Select("epoch").
			Where("workspace_id = ? AND agent_id = ?", workspaceID, agentID).
			Take(&stored).Error; err != nil {
			return err
		}
		epoch = stored.Epoch
		return nil
	})
	if err != nil {
		return 0, err
	}
	return epoch, nil
}

// Refresh is the coalesced heartbeat write. The CAS on (owner_node_id, epoch)
// makes it a no-op (ErrOwnershipLost) once another replica has taken over, so a
// stale owner stops claiming an agent it no longer holds.
func (d *GormSessionDirectory) Refresh(ctx context.Context, workspaceID, agentID uuid.UUID, nodeID string, epoch int64) error {
	now := d.now()
	res := d.db.WithContext(ctx).Model(&models.AgentSessionDirectoryEntry{}).
		Where("workspace_id = ? AND agent_id = ? AND owner_node_id = ? AND epoch = ?", workspaceID, agentID, nodeID, epoch).
		Updates(map[string]any{"last_seen_at": now, "updated_at": now})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrOwnershipLost
	}
	return nil
}

// Release clears ownership iff the caller still holds (node, epoch). A row that
// a newer owner already took over (different node/epoch) is left untouched, so
// a late release from a superseded owner cannot delete the live owner's claim.
func (d *GormSessionDirectory) Release(ctx context.Context, workspaceID, agentID uuid.UUID, nodeID string, epoch int64) error {
	return d.db.WithContext(ctx).
		Where("workspace_id = ? AND agent_id = ? AND owner_node_id = ? AND epoch = ?", workspaceID, agentID, nodeID, epoch).
		Delete(&models.AgentSessionDirectoryEntry{}).Error
}

// Lookup returns the current owner and whether it is fresh.
func (d *GormSessionDirectory) Lookup(ctx context.Context, workspaceID, agentID uuid.UUID) (*OwnerEntry, bool, error) {
	var row models.AgentSessionDirectoryEntry
	err := d.db.WithContext(ctx).
		Where("workspace_id = ? AND agent_id = ?", workspaceID, agentID).
		Take(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	entry := &OwnerEntry{
		NodeID:      row.OwnerNodeID,
		ForwardAddr: row.OwnerForwardAddr,
		Epoch:       row.Epoch,
		LastSeenAt:  row.LastSeenAt,
	}
	return entry, d.fresh(row.LastSeenAt), nil
}

// OnlineCount counts agents in a workspace with a fresh owner anywhere.
func (d *GormSessionDirectory) OnlineCount(ctx context.Context, workspaceID uuid.UUID) (int, error) {
	var n int64
	if err := d.db.WithContext(ctx).Model(&models.AgentSessionDirectoryEntry{}).
		Where("workspace_id = ? AND last_seen_at > ?", workspaceID, d.now().Add(-d.staleAfter)).
		Count(&n).Error; err != nil {
		return 0, err
	}
	return int(n), nil
}

// IsOnline reports whether a specific agent has a fresh owner anywhere.
func (d *GormSessionDirectory) IsOnline(ctx context.Context, workspaceID, agentID uuid.UUID) (bool, error) {
	_, fresh, err := d.Lookup(ctx, workspaceID, agentID)
	if err != nil {
		return false, err
	}
	return fresh, nil
}

// fresh reports whether a last-seen timestamp is within the staleness window.
func (d *GormSessionDirectory) fresh(lastSeen time.Time) bool {
	return d.now().Sub(lastSeen) <= d.staleAfter
}
