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
)

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
