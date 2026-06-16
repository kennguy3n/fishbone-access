package models

import (
	"time"

	"github.com/google/uuid"
)

// AgentSessionDirectoryEntry is the durable record of WHICH control-plane
// replica currently owns an agent's live outbound tunnel. The platform runs the
// pam-gateway binary as multiple horizontally-scaled replicas behind a load
// balancer, but an agent's mTLS tunnel terminates on exactly ONE replica (its
// yamux session lives only in that replica's memory). A privileged session-open
// that needs DialThroughAgent may land on a DIFFERENT replica, which has no
// local tunnel for that agent. This row is the cross-replica signal the broker
// uses to forward such a dial to the replica that actually holds the tunnel,
// instead of failing closed when the session merely lands on the "wrong" node.
//
// Ownership is single-writer per (workspace_id, agent_id): the owning replica
// claims the row when an agent registers, refreshes LastSeenAt on heartbeat
// (coalesced — never per-dial), and clears it on disconnect. A reconnect
// (possibly to a different replica) takes over ownership by bumping Epoch, and
// every refresh/release is conditioned on the claiming replica still holding
// that exact Epoch — a compare-and-set so a stale owner whose tunnel already
// died can never clobber or delete a newer owner's claim.
//
// It does NOT embed Base: there is at most one row per (workspace, agent) and
// it is HARD-deleted on disconnect (a fast-reconnecting agent must not bloat
// the table with soft-delete tombstones — important at 5k-tenant scale), so the
// identity is the (workspace_id, agent_id) pair rather than a surrogate UUID and
// there is no soft-delete column. It is tenant-scoped (workspace_id) and so
// carries the same RLS tenant_isolation policy as the rest of the schema (see
// migration 0080) — a forwarded dial can never cross a tenant boundary.
type AgentSessionDirectoryEntry struct {
	WorkspaceID uuid.UUID `gorm:"type:uuid;primaryKey" json:"workspace_id"`
	AgentID     uuid.UUID `gorm:"type:uuid;primaryKey" json:"agent_id"`
	// OwnerNodeID identifies the replica that currently holds the agent's live
	// tunnel (its configured node identity, defaulted to hostname/pod name).
	OwnerNodeID string `gorm:"not null" json:"owner_node_id"`
	// OwnerForwardAddr is the owner's INTERNAL forward-listener address other
	// replicas dial (replica-to-replica mTLS) to open a stream to this agent. It
	// is never exposed to tenants and is distinct from the public relay address
	// agents dial out to.
	OwnerForwardAddr string `gorm:"not null" json:"owner_forward_addr"`
	// Epoch is the monotonically increasing ownership generation. It is bumped on
	// every (re)claim so refresh/release can compare-and-set against the exact
	// generation the caller claimed, making a stale owner's late write a no-op.
	Epoch int64 `gorm:"not null;default:1" json:"epoch"`
	// LastSeenAt is refreshed on the owner's heartbeat (coalesced). A reader
	// treats an entry older than the staleness window as a crashed owner and
	// fails a forwarded dial closed rather than dialing a dead node.
	LastSeenAt time.Time `gorm:"not null" json:"last_seen_at"`
	CreatedAt  time.Time `gorm:"not null;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt  time.Time `gorm:"not null;default:CURRENT_TIMESTAMP" json:"updated_at"`
}

// TableName pins the table name so the GORM auto-migrate (dev/test) and the SQL
// migration (production) agree.
func (AgentSessionDirectoryEntry) TableName() string { return "agent_session_directory" }
