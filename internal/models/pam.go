package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

// PAM protocol identifiers. A PAMTarget is reachable over exactly one of these
// wire protocols, and the pam-gateway binds one ConnHandler per protocol.
const (
	PAMProtocolSSH      = "ssh"
	PAMProtocolPostgres = "postgres"
	PAMProtocolMySQL    = "mysql"
	PAMProtocolK8sExec  = "k8s-exec"
	PAMProtocolRDP      = "rdp"
	PAMProtocolVNC      = "vnc"
	PAMProtocolMongoDB  = "mongodb"
	PAMProtocolRedis    = "redis"
	PAMProtocolMSSQL    = "mssql"
	PAMProtocolHTTP     = "http"
)

// pamProtocols is the canonical, ordered set of wire protocols the gateway
// supports. It is the single source of truth: the vault's validProtocol gate
// (PAM target CRUD) and the DB-level CHECK constraint added in
// 0011_pam_protocol_expansion.sql both derive their accepted set from here, so
// adding a protocol is a one-line change plus a migration. Keep this in sync
// with the listeners bound in cmd/pam-gateway and the CHECK migration.
var pamProtocols = []string{
	PAMProtocolSSH,
	PAMProtocolPostgres,
	PAMProtocolMySQL,
	PAMProtocolK8sExec,
	PAMProtocolRDP,
	PAMProtocolVNC,
	PAMProtocolMongoDB,
	PAMProtocolRedis,
	PAMProtocolMSSQL,
	PAMProtocolHTTP,
}

// PAMProtocols returns the supported wire protocols in canonical order. The
// returned slice is a copy so callers cannot mutate the package-level source of
// truth.
func PAMProtocols() []string {
	out := make([]string, len(pamProtocols))
	copy(out, pamProtocols)
	return out
}

// IsValidPAMProtocol reports whether p is a supported PAM wire protocol.
func IsValidPAMProtocol(p string) bool {
	for _, proto := range pamProtocols {
		if proto == p {
			return true
		}
	}
	return false
}

// PAM connect-token states. A token is minted "pending", flipped to "consumed"
// the first time the gateway redeems it (one-shot), and "expired" once its
// lease window closes without being used. Redemption is an atomic
// pending → consumed transition so a token can authorize at most one session.
const (
	PAMConnectTokenPending  = "pending"
	PAMConnectTokenConsumed = "consumed"
	PAMConnectTokenExpired  = "expired"
)

// PAM session states. A session is "active" while the proxy holds the
// bidirectional stream open, "closed" on a clean operator-driven teardown, and
// "terminated" when an admin kills it via the takeover registry.
const (
	PAMSessionActive     = "active"
	PAMSessionClosed     = "closed"
	PAMSessionTerminated = "terminated"
)

// PAM command decisions, mirroring the 1C policy engine's grant/deny vocabulary
// plus a "step_up" outcome that demands a fresh MFA assertion before the
// command is forwarded. These are the values written to
// pam_session_commands.decision and to the audit chain metadata.
const (
	PAMDecisionAllow  = "allow"
	PAMDecisionDeny   = "deny"
	PAMDecisionStepUp = "step_up"
)

// PAMTarget is a privileged resource the gateway proxies to (an SSH host, a
// Postgres/MySQL database, or a Kubernetes API server). It is the credential
// vault row: SecretEnvelope holds the AES-256-GCM sealed upstream credential
// (never plaintext), sealed by the per-workspace EnvelopeEncryptor with the
// target's own ID bound as AES-GCM AAD so a ciphertext copied to another row
// fails to open. SecretKeyVersion records which DEK version sealed it so the
// encryptor resolves the right key across rotations.
//
// Address is the upstream dial target (host:port). Username is the upstream
// account the injected credential authenticates as. RequireMFA gates secret
// reveal / connect behind a step-up MFA assertion per the shared iam-core
// contract.
type PAMTarget struct {
	Base
	WorkspaceID      uuid.UUID      `gorm:"type:uuid;index;not null;uniqueIndex:uq_pam_targets_name,where:deleted_at IS NULL" json:"workspace_id"`
	Name             string         `gorm:"not null;uniqueIndex:uq_pam_targets_name,where:deleted_at IS NULL" json:"name"`
	Protocol         string         `gorm:"not null" json:"protocol"`
	Address          string         `gorm:"not null" json:"address"`
	Username         string         `json:"username"`
	Config           datatypes.JSON `json:"config,omitempty"`
	SecretEnvelope   string         `json:"-"`
	SecretKeyVersion int            `gorm:"not null;default:1" json:"-"`
	RequireMFA       bool           `gorm:"not null;default:false" json:"require_mfa"`
	// LeaseTTLSeconds caps how long a connect token minted for this target stays
	// redeemable. Zero falls back to the broker's default.
	LeaseTTLSeconds int        `gorm:"not null;default:0" json:"lease_ttl_seconds"`
	SecretRotatedAt *time.Time `json:"secret_rotated_at,omitempty"`
}

// PAMConnectToken is a one-shot, short-lived credential an operator presents to
// the gateway to open a privileged session. The raw token is returned to the
// caller exactly once at mint time and never persisted: only TokenHash (a
// SHA-256 of the raw token) is stored, so a database read cannot recover a
// usable token. Redemption atomically flips State pending → consumed, so a
// token authorizes at most one session (replay-safe). ExpiresAt is the lease
// boundary.
type PAMConnectToken struct {
	Base
	WorkspaceID uuid.UUID  `gorm:"type:uuid;index;not null" json:"workspace_id"`
	TargetID    uuid.UUID  `gorm:"type:uuid;index;not null" json:"target_id"`
	TokenHash   string     `gorm:"uniqueIndex;not null" json:"-"`
	Subject     string     `gorm:"index;not null" json:"subject"`
	State       string     `gorm:"not null;default:pending" json:"state"`
	ExpiresAt   time.Time  `gorm:"not null" json:"expires_at"`
	ConsumedAt  *time.Time `json:"consumed_at,omitempty"`
	SessionID   *uuid.UUID `gorm:"type:uuid;index" json:"session_id,omitempty"`
	// LeaseID binds the token to the JIT lease that authorized it. When set, the
	// broker re-validates the lease is live (granted, not revoked, not expired)
	// at both mint and redeem time, so a target's sealed credential is only ever
	// brokered into a session a live lease authorizes. Nil for the legacy
	// direct-mint path (a token minted without a lease, gated solely by the
	// target's own MFA requirement).
	LeaseID *uuid.UUID `gorm:"type:uuid;index" json:"lease_id,omitempty"`
}

// PAMSession is one proxied privileged connection. It is created when a connect
// token is redeemed and updated as the session proceeds. ReplayKey is the
// canonical storage key of the recorded I/O blob
// (sessions/{id}/replay.bin) so the audit/replay UI can fetch it. TerminatedBy
// records the admin who killed an active session via takeover.
type PAMSession struct {
	Base
	WorkspaceID  uuid.UUID  `gorm:"type:uuid;index;not null" json:"workspace_id"`
	TargetID     uuid.UUID  `gorm:"type:uuid;index;not null" json:"target_id"`
	Subject      string     `gorm:"index;not null" json:"subject"`
	Protocol     string     `gorm:"not null" json:"protocol"`
	State        string     `gorm:"not null;default:active" json:"state"`
	ClientAddr   string     `json:"client_addr,omitempty"`
	ReplayKey    string     `json:"replay_key,omitempty"`
	StartedAt    time.Time  `json:"started_at"`
	EndedAt      *time.Time `json:"ended_at,omitempty"`
	TerminatedBy string     `json:"terminated_by,omitempty"`
	// LeaseID links the session to the JIT lease that authorized it (nil for the
	// legacy direct-mint path). The expiry/revoke sweep uses it to find and tear
	// down sessions whose lease is no longer live.
	LeaseID *uuid.UUID `gorm:"type:uuid;index" json:"lease_id,omitempty"`
	// Paused is the operator-controlled soft-pause flag. While true the gateway
	// reconciler holds the session's operator→upstream byte path (buffered, not
	// dropped) so no further wire bytes reach the upstream until an operator
	// resumes or terminates. It is the durable, cross-process intent the gateway
	// loop reconciles against the in-process pause gate; PausedBy/PausedAt record
	// who paused it and when for the audit trail and the live-sessions console.
	Paused   bool       `gorm:"not null;default:false" json:"paused"`
	PausedBy string     `json:"paused_by,omitempty"`
	PausedAt *time.Time `json:"paused_at,omitempty"`
}

// PAMSessionCommand is one logged command (SSH) or statement (SQL) observed on
// a session, with the policy decision the gateway applied. Seq is a per-session
// monotonic counter so the command transcript reconstructs in order
// independent of wall-clock timestamps. Rows are append-only; each also lands
// in the workspace audit hash chain for tamper evidence.
type PAMSessionCommand struct {
	Base
	WorkspaceID uuid.UUID `gorm:"type:uuid;index;not null;uniqueIndex:uq_pam_cmds_session_seq,priority:1" json:"workspace_id"`
	SessionID   uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:uq_pam_cmds_session_seq,priority:2" json:"session_id"`
	Seq         int64     `gorm:"not null;default:0;uniqueIndex:uq_pam_cmds_session_seq,priority:3" json:"seq"`
	Command     string    `gorm:"not null" json:"command"`
	Decision    string    `gorm:"not null;default:allow" json:"decision"`
	Reason      string    `json:"reason,omitempty"`
}
