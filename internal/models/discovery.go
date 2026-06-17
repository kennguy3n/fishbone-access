package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

// Feature E — account/asset auto-discovery + auto-onboarding.
//
// These models persist what a discovery sweep FOUND (assets and DB-internal
// accounts), the sweep RUNS themselves (for history/observability), and the
// per-workspace AUTO-ONBOARDING POLICY that turns matching unmanaged assets
// into managed PAM targets on a schedule. They are all workspace-scoped and
// therefore join the 0024 tenant-isolation RLS regime (see migration 0070).

// Discovery sources. A discovered row records WHICH source produced it so the
// reconciler can key idempotent upserts on (workspace, source, external_id) and
// the UI can facet by origin.
const (
	// DiscoverySourceAgentSweep is an operator-initiated network sweep that
	// probes operator-specified hosts/CIDRs for reachable privileged-service
	// ports THROUGH a bound outbound agent (never a direct internet scan).
	DiscoverySourceAgentSweep = "agent_sweep"
	// DiscoverySourceConnector is a cloud connector's native inventory API
	// (e.g. AWS EC2/RDS, Azure VMs/SQL) enumerated with the connector's own
	// configured credentials.
	DiscoverySourceConnector = "connector_inventory"
	// DiscoverySourceDBAccounts enumerates DB-internal roles/users on an
	// already-registered PAM database target (Postgres pg_roles, MySQL
	// mysql.user) through the leased connection path.
	DiscoverySourceDBAccounts = "db_accounts"
)

// Discovered-item lifecycle status. The reconciler classifies every row on each
// sweep so the inventory surface can show managed/unmanaged/orphan at a glance.
const (
	// DiscoveryStatusUnmanaged is a candidate: it exists upstream but is not yet
	// a managed PAM target/grant. This is what "onboard" acts on.
	DiscoveryStatusUnmanaged = "unmanaged"
	// DiscoveryStatusManaged means the item is already (or now) a PAM target /
	// active grant — nothing to do.
	DiscoveryStatusManaged = "managed"
	// DiscoveryStatusOrphan applies to ACCOUNTS only: the account exists
	// upstream but has no live grant. The account reconciler links this to the
	// existing lifecycle orphan reconciler for connector-backed identities.
	DiscoveryStatusOrphan = "orphan"
	// DiscoveryStatusIgnored is an operator disposition: hide this row from the
	// candidate list (re-running a sweep must not resurrect it as unmanaged).
	DiscoveryStatusIgnored = "ignored"
)

// DiscoveryScan trigger + status.
const (
	DiscoveryTriggerManual    = "manual"
	DiscoveryTriggerScheduled = "scheduled"

	DiscoveryScanRunning   = "running"
	DiscoveryScanCompleted = "completed"
	DiscoveryScanFailed    = "failed"
)

// DiscoveredAsset is one host/database found by a discovery source that is a
// candidate to onboard as a PAMTarget. It is upserted idempotently on
// (workspace_id, source, external_id): re-running a sweep updates last_seen_at
// and metadata in place rather than duplicating. When the asset is onboarded
// (manually or by policy) target_id is set and status becomes managed.
type DiscoveredAsset struct {
	Base
	WorkspaceID uuid.UUID `gorm:"type:uuid;not null;index:idx_discovered_assets_ws_status,priority:1;uniqueIndex:uq_discovered_assets_identity,priority:1,where:deleted_at IS NULL" json:"workspace_id"`
	// Source is one of the DiscoverySource* constants.
	Source string `gorm:"not null;uniqueIndex:uq_discovered_assets_identity,priority:2,where:deleted_at IS NULL" json:"source"`
	// ExternalID is the source-stable identity used as the upsert key — e.g.
	// "ec2:i-0abc", "rds:mydb", "host:10.0.0.5:22". Together with (workspace,
	// source) it uniquely names the asset across re-scans.
	ExternalID string `gorm:"not null;uniqueIndex:uq_discovered_assets_identity,priority:3,where:deleted_at IS NULL" json:"external_id"`
	// Name is a friendly display label (instance name, hostname).
	Name string `gorm:"not null;default:''" json:"name"`
	// Protocol is the inferred PAM protocol (ssh, postgres, rdp, …) used to
	// pre-fill the onboard form. Empty when the source cannot infer one.
	Protocol string `gorm:"not null;default:''" json:"protocol"`
	// Address is host:port (agent sweep) or the connector-reported endpoint.
	Address string `gorm:"not null;default:''" json:"address"`
	// Status is one of the DiscoveryStatus* constants.
	Status string `gorm:"not null;default:unmanaged;index:idx_discovered_assets_ws_status,priority:2" json:"status"`
	// AgentID is the outbound agent that reached the asset (agent_sweep), used
	// to pre-bind the onboarded target. Nil for connector inventory.
	AgentID *uuid.UUID `gorm:"type:uuid" json:"agent_id,omitempty"`
	// ConnectorID is the cloud connector that enumerated the asset
	// (connector_inventory). Nil for agent sweep.
	ConnectorID *uuid.UUID `gorm:"type:uuid" json:"connector_id,omitempty"`
	// TargetID links to the PAMTarget once the asset is onboarded.
	TargetID *uuid.UUID `gorm:"type:uuid" json:"target_id,omitempty"`
	// PendingTargetID records the PAMTarget that OnboardAsset created while the
	// asset is still being linked. It is set right after target creation and
	// cleared atomically when the link succeeds; if the link fails, the
	// reconcile sweep uses it to re-link the stranded asset deterministically to
	// the exact target the onboard created — regardless of any address override
	// — instead of relying on an endpoint heuristic that an override could miss.
	PendingTargetID *uuid.UUID `gorm:"type:uuid" json:"-"`
	// Metadata carries source-specific facts (cloud region, instance type, OS,
	// db engine, tags) shown in the asset detail drawer. Never holds secrets.
	Metadata datatypes.JSON `json:"metadata,omitempty"`
	// PolicyMatched is set by the auto-onboarding evaluator when the asset
	// matches an enabled policy rule but was not (or not yet) auto-created — it
	// surfaces "recommended to onboard" in the UI.
	PolicyMatched bool `gorm:"not null;default:false" json:"policy_matched"`
	// FirstSeenAt / LastSeenAt bound the asset's observation window. LastSeenAt
	// advances on every sweep that still sees it; a stale LastSeenAt is how the
	// UI flags assets that may have been decommissioned upstream.
	FirstSeenAt time.Time `gorm:"not null" json:"first_seen_at"`
	LastSeenAt  time.Time `gorm:"not null;index:idx_discovered_assets_ws_status,priority:3,sort:desc" json:"last_seen_at"`
}

// TableName pins the singular table name created by migration 0070 so GORM's
// pluraliser (used by the SQLite AutoMigrate test path) agrees with production.
func (DiscoveredAsset) TableName() string { return "discovered_assets" }

// DiscoveredAccount is one DB-internal role/user enumerated on an
// already-registered PAM database target. It complements the connector-level
// orphan reconciler (which covers SaaS identities): this covers accounts that
// live INSIDE the database itself. Upserted idempotently on (workspace_id,
// target_id, username).
type DiscoveredAccount struct {
	Base
	WorkspaceID uuid.UUID `gorm:"type:uuid;not null;index:idx_discovered_accounts_ws_status,priority:1;uniqueIndex:uq_discovered_accounts_identity,priority:1,where:deleted_at IS NULL" json:"workspace_id"`
	// TargetID is the PAM database target the account was enumerated on.
	TargetID uuid.UUID `gorm:"type:uuid;not null;index;uniqueIndex:uq_discovered_accounts_identity,priority:2,where:deleted_at IS NULL" json:"target_id"`
	// Username is the DB role/user name (the upsert key within a target).
	Username string `gorm:"not null;uniqueIndex:uq_discovered_accounts_identity,priority:3,where:deleted_at IS NULL" json:"username"`
	// Source is always DiscoverySourceDBAccounts today; kept explicit for
	// symmetry with assets and future account sources.
	Source string `gorm:"not null;default:db_accounts" json:"source"`
	// Status is one of the DiscoveryStatus* constants (managed/unmanaged/orphan).
	Status string `gorm:"not null;default:unmanaged;index:idx_discovered_accounts_ws_status,priority:2" json:"status"`
	// CanLogin / Superuser are the privilege facts that make an unmanaged
	// account interesting to an auditor; surfaced as risk badges in the UI.
	CanLogin  bool `gorm:"not null;default:false" json:"can_login"`
	Superuser bool `gorm:"not null;default:false" json:"superuser"`
	// Attributes carries the remaining engine-specific role flags
	// (createrole, replication, member_of …) for the detail drawer.
	Attributes  datatypes.JSON `json:"attributes,omitempty"`
	FirstSeenAt time.Time      `gorm:"not null" json:"first_seen_at"`
	LastSeenAt  time.Time      `gorm:"not null;index:idx_discovered_accounts_ws_status,priority:3,sort:desc" json:"last_seen_at"`
}

func (DiscoveredAccount) TableName() string { return "discovered_accounts" }

// DiscoveryScan is the durable record of one sweep run — its source, trigger,
// outcome counts, and any error. It powers the "recent scans" timeline and lets
// the workflow engine record scheduled sweeps without per-tenant metrics.
type DiscoveryScan struct {
	Base
	WorkspaceID uuid.UUID `gorm:"type:uuid;not null;index:idx_discovery_scans_ws_started,priority:1" json:"workspace_id"`
	// Source is one of the DiscoverySource* constants.
	Source string `gorm:"not null;default:''" json:"source"`
	// Trigger is manual (operator-initiated) or scheduled (workflow engine).
	Trigger string `gorm:"not null;default:manual" json:"trigger"`
	// Status is running/completed/failed.
	Status string `gorm:"not null;default:running" json:"status"`
	Actor  string `gorm:"not null;default:''" json:"actor"`
	// Outcome counts (set-based, aggregate per scan — never per-tenant metrics).
	AssetsFound    int        `gorm:"not null;default:0" json:"assets_found"`
	AssetsNew      int        `gorm:"not null;default:0" json:"assets_new"`
	AccountsFound  int        `gorm:"not null;default:0" json:"accounts_found"`
	OnboardedCount int        `gorm:"not null;default:0" json:"onboarded_count"`
	StartedAt      time.Time  `gorm:"not null;index:idx_discovery_scans_ws_started,priority:2,sort:desc" json:"started_at"`
	FinishedAt     *time.Time `json:"finished_at,omitempty"`
	// Error is the failure detail when status is failed (never holds secrets).
	Error string `gorm:"not null;default:''" json:"error,omitempty"`
	// Params records the scan inputs (cidrs/hosts, agent_id, connector_id) for
	// reproducibility and audit. Never holds secrets.
	Params datatypes.JSON `json:"params,omitempty"`
}

func (DiscoveryScan) TableName() string { return "discovery_scans" }

// AutoOnboardingPolicy is the per-workspace, opt-in (default OFF) policy that
// turns matching unmanaged assets into managed PAM targets on each sweep. There
// is exactly one row per workspace.
//
// Safety boundary (documented in the PR): auto-onboarding only ever creates the
// managed TARGET record; it never grants standing privileged access. Every
// created target is registered with RequireLease semantics, so actual access
// still flows through the normal request/lease/approval path and is audited.
// When CreateTargets is false (or no onboarding credential is configured) the
// policy runs in FLAG-ONLY mode: matching assets are marked PolicyMatched and
// surfaced as "recommended", but no target is created without an explicit,
// credentialed onboard.
type AutoOnboardingPolicy struct {
	Base
	WorkspaceID uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:uq_auto_onboarding_policy_ws,where:deleted_at IS NULL" json:"workspace_id"`
	// Enabled gates the whole policy. Safe default OFF.
	Enabled bool `gorm:"not null;default:false" json:"enabled"`
	// CreateTargets, when true AND an onboarding credential is sealed, lets the
	// sweep create real PAM targets for matched assets. When false the policy is
	// flag-only.
	CreateTargets bool `gorm:"not null;default:false" json:"create_targets"`
	// RequireLease forces every auto-created target to require a lease (no
	// standing access). It is intentionally not operator-clearable below true
	// in the service layer — auto-created targets always require a lease.
	RequireLease bool `gorm:"not null;default:true" json:"require_lease"`
	// Rules is the JSON-encoded []AutoOnboardRule the evaluator matches assets
	// against. Defined in the discovery service package.
	Rules datatypes.JSON `json:"rules,omitempty"`
	// DefaultAgentID is bound to auto-created targets when a rule does not name
	// its own agent (and the asset was found via that agent).
	DefaultAgentID *uuid.UUID `gorm:"type:uuid" json:"default_agent_id,omitempty"`
	// ActiveSweepEnabled gates the scheduled ACTIVE network sweep run on every
	// scheduled-sweep tick (separate from connector inventory + onboarding,
	// which Enabled gates). Safe default OFF: a workspace must deliberately opt
	// in, name the agent that performs the sweep, and supply a bounded target
	// list before the engine probes anything.
	ActiveSweepEnabled bool `gorm:"not null;default:false" json:"active_sweep_enabled"`
	// ActiveSweepAgentID is the agent the scheduled active sweep dials through.
	// Required (in the service layer) when ActiveSweepEnabled is true — a sweep
	// only ever probes THROUGH an agent in the workspace, never directly.
	ActiveSweepAgentID *uuid.UUID `gorm:"type:uuid" json:"active_sweep_agent_id,omitempty"`
	// ActiveSweepTargets is the JSON-encoded ActiveSweepTargets (hosts/cidrs/
	// ports) the scheduled sweep probes. Bounded by Config.MaxProbeTargets at
	// save time so a scheduled sweep can never fan out to an unbounded space.
	ActiveSweepTargets datatypes.JSON `json:"active_sweep_targets,omitempty"`
	// Sealed onboarding credential used for auto-created targets. The plaintext
	// is AES-256-GCM sealed with the workspace DEK (AAD = policy id) and is
	// NEVER returned in API responses. CredentialUsername is non-secret and is
	// shown so an admin can confirm which service account will be used.
	CredentialUsername string `gorm:"not null;default:''" json:"credential_username,omitempty"`
	CredentialEnvelope string `gorm:"not null;default:''" json:"-"`
	CredentialKeyVer   int    `gorm:"not null;default:0" json:"-"`
	// HasCredential is a derived, non-secret flag the API sets so the UI can
	// show whether a credential is configured without exposing it.
	HasCredential bool   `gorm:"-" json:"has_credential"`
	UpdatedBy     string `gorm:"not null;default:''" json:"updated_by,omitempty"`
}

func (AutoOnboardingPolicy) TableName() string { return "auto_onboarding_policies" }
