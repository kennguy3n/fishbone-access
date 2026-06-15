package models

import (
	"time"

	"github.com/google/uuid"
)

// Outbound connector-agent lifecycle states. An agent row is created
// "enrolled" when its one-shot enrollment token is redeemed and a client
// certificate is issued. The relay flips it "online" while a live mTLS tunnel
// is held and "offline" when that tunnel drops. "revoked" is terminal: the
// relay refuses the agent's certificate and the gateway will never broker
// through it again. The status here is the durable, control-plane view of
// health that the UI renders; the live connection itself lives only in the
// relay process memory (see internal/broker).
const (
	AgentStatusEnrolled = "enrolled"
	AgentStatusOnline   = "online"
	AgentStatusOffline  = "offline"
	AgentStatusRevoked  = "revoked"
)

// Agent enrollment-token states, mirroring PAMConnectToken: a token is minted
// "pending", flipped to "consumed" the first (and only) time it is redeemed,
// and "expired" once its window closes without being used. Redemption is an
// atomic pending → consumed transition so a single token can enroll at most one
// agent (replay-safe).
const (
	AgentEnrollTokenPending  = "pending"
	AgentEnrollTokenConsumed = "consumed"
	AgentEnrollTokenExpired  = "expired"
)

// Reachable-target binding kinds. A binding declares one network destination an
// agent can reach inside the customer's private network, so the relay can route
// a DialThroughAgent for an address to an agent that actually has a path to it.
const (
	AgentReachKindCIDR     = "cidr"     // an IP range, e.g. 10.0.0.0/24
	AgentReachKindHost     = "host"     // an exact host or host:port
	AgentReachKindHostname = "hostname" // a hostname or *.suffix wildcard
)

// TargetAgent is an outbound-only connector an SME runs on one host inside their
// private network. It dials OUT to the control-plane relay over mTLS and brokers
// privileged sessions to private targets, so the customer never opens an inbound
// firewall port. Identity is the issued client certificate: CertFingerprint is
// the SHA-256 of its DER, which the relay matches against the presented peer
// certificate to bind a live tunnel to this row (defense in depth on top of the
// agent-CA trust check). The row is the durable registration and health record;
// the live tunnel itself is held only in the relay process.
type TargetAgent struct {
	Base
	WorkspaceID uuid.UUID `gorm:"type:uuid;index;not null;uniqueIndex:uq_agents_name,where:deleted_at IS NULL" json:"workspace_id"`
	Name        string    `gorm:"not null;uniqueIndex:uq_agents_name,where:deleted_at IS NULL" json:"name"`
	// CertFingerprint is the lowercase hex SHA-256 of the issued client
	// certificate (DER). Unique so a fingerprint identifies exactly one agent.
	CertFingerprint string     `gorm:"uniqueIndex;not null" json:"cert_fingerprint"`
	CertSerial      string     `gorm:"not null" json:"cert_serial"`
	CertNotAfter    time.Time  `gorm:"not null" json:"cert_not_after"`
	Status          string     `gorm:"not null;default:enrolled" json:"status"`
	LastSeenAt      *time.Time `json:"last_seen_at,omitempty"`
	AgentVersion    string     `json:"agent_version,omitempty"`
	Platform        string     `json:"platform,omitempty"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
	RevokedBy       string     `json:"revoked_by,omitempty"`
}

// TableName pins the table so the GORM auto-migrate (dev/test) and the SQL
// migration (production) agree on "agents" rather than GORM's pluralized
// "target_agents".
func (TargetAgent) TableName() string { return "agents" }

// AgentEnrollmentToken is a one-shot, short-lived secret an operator generates
// to enroll exactly one agent. It mirrors PAMConnectToken: the raw token is
// returned once at mint time and never persisted — only TokenHash (a SHA-256 of
// the raw token) is stored, so a database read cannot recover a usable token.
// Redemption atomically flips State pending → consumed and binds AgentID, so a
// token enrolls at most one agent.
type AgentEnrollmentToken struct {
	Base
	WorkspaceID uuid.UUID  `gorm:"type:uuid;index;not null" json:"workspace_id"`
	TokenHash   string     `gorm:"uniqueIndex;not null" json:"-"`
	Name        string     `gorm:"not null" json:"name"`
	State       string     `gorm:"not null;default:pending" json:"state"`
	ExpiresAt   time.Time  `gorm:"not null" json:"expires_at"`
	ConsumedAt  *time.Time `json:"consumed_at,omitempty"`
	AgentID     *uuid.UUID `gorm:"type:uuid;index" json:"agent_id,omitempty"`
	CreatedBy   string     `gorm:"not null" json:"created_by"`
}

func (AgentEnrollmentToken) TableName() string { return "agent_enrollment_tokens" }

// AgentReachableTarget is one network destination an agent advertises it can
// reach. Bindings come from two sources that the relay unions: the operator
// binding a registered PAM target to an agent (durable, what the UI shows) and
// the agent self-reporting its reachable CIDRs on registration. The relay uses
// the set to pick an agent for a DialThroughAgent and to fail closed when no
// online agent covers the requested address.
type AgentReachableTarget struct {
	Base
	WorkspaceID uuid.UUID `gorm:"type:uuid;index;not null;uniqueIndex:uq_agent_reach,priority:1,where:deleted_at IS NULL" json:"workspace_id"`
	AgentID     uuid.UUID `gorm:"type:uuid;index;not null;uniqueIndex:uq_agent_reach,priority:2,where:deleted_at IS NULL" json:"agent_id"`
	Pattern     string    `gorm:"not null;uniqueIndex:uq_agent_reach,priority:3,where:deleted_at IS NULL" json:"pattern"`
	Kind        string    `gorm:"not null" json:"kind"`
	// TargetID, when set, links the binding to the PAM target it was created for
	// (the operator "reach this target via this agent" action). Self-reported
	// CIDRs leave it nil.
	TargetID *uuid.UUID `gorm:"type:uuid;index" json:"target_id,omitempty"`
}

func (AgentReachableTarget) TableName() string { return "agent_reachable_targets" }
