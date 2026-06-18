// Package discovery implements account/asset auto-discovery and auto-onboarding
// (Feature E). It finds hosts/databases and DB-internal accounts that are NOT
// yet onboarded, reconciles them into a single tenant-scoped inventory
// classified managed/unmanaged/orphan, and — opt-in, default OFF — turns
// matching unmanaged assets into managed PAM targets on a schedule.
//
// Sources (all real; none fabricated):
//
//   - Agent network sweep: probes operator-specified hosts/CIDRs for reachable
//     privileged-service ports THROUGH a bound outbound agent (broker dial
//     seam), with strict timeouts and bounded concurrency. Never a direct
//     internet scan — it refuses anything not reachable through an agent.
//   - Connector asset inventory: enumerates a cloud connector's native
//     inventory via the optional access.AssetDiscoverer capability (AWS EC2/RDS,
//     Azure VMs/SQL today) using the connector's existing credentials.
//   - DB account enumeration: lists DB-internal roles/users (Postgres pg_roles,
//     MySQL mysql.user) on an already-registered PAM database target and
//     reconciles them against managed access.
//
// Safety boundary: auto-onboarding only ever creates the managed TARGET record;
// it never grants standing privileged access. Actual access always flows
// through the normal request/lease path and is audit-chained.
package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// Sentinel errors mapped to HTTP status codes by the handler layer.
var (
	// ErrValidation is a bad request (missing/invalid input).
	ErrValidation = errors.New("discovery: validation")
	// ErrNotFound is an unknown asset/account/scan/policy.
	ErrNotFound = errors.New("discovery: not found")
	// ErrConflict is a state conflict (e.g. onboarding an already-managed asset).
	ErrConflict = errors.New("discovery: conflict")
	// ErrUnsupported is a capability the target/connector does not support
	// (e.g. enumerating accounts on a non-database target, or asset inventory on
	// a connector with no inventory API).
	ErrUnsupported = errors.New("discovery: unsupported")
	// ErrAgentBindFailed signals a PARTIAL success from OnboardAsset: the PAM
	// target was created and the discovered asset linked to it (audited), but
	// binding the target to its outbound agent failed. The target is fully
	// usable via direct dial and the agent association can be retried from
	// target settings, so callers must treat the onboard as done (e.g. 201 +
	// warning, counted as onboarded) rather than a hard failure. Returned
	// alongside a non-nil *PAMTarget.
	ErrAgentBindFailed = errors.New("discovery: agent bind failed")
)

// Config tunes the discovery engine. It is safe-by-default: zero values fall
// back to the conservative defaults applied in withDefaults so a degraded boot
// (or a test) never probes with an unbounded timeout or concurrency.
type Config struct {
	// ProbeTimeout bounds a single host:port reachability probe through an
	// agent. Default 3s.
	ProbeTimeout time.Duration
	// ProbeConcurrency caps the number of concurrent probes per sweep so a
	// /24 sweep cannot exhaust the agent tunnel or the engine's sockets.
	// Default 16.
	ProbeConcurrency int
	// MaxProbeTargets caps host*port fan-out for one sweep request — a hard
	// guard against an operator pasting an enormous CIDR. Default 1024.
	MaxProbeTargets int
	// DBDialTimeout bounds a DB account-enumeration connection. Default 10s.
	DBDialTimeout time.Duration
	// SweepInterval is the scheduled-sweep cadence in the workflow engine.
	// Default 6h. Only workspaces with an enabled auto-onboarding policy are
	// swept, so this stays cheap across a 5k-tenant fleet.
	SweepInterval time.Duration
}

func (c Config) withDefaults() Config {
	if c.ProbeTimeout <= 0 {
		c.ProbeTimeout = 3 * time.Second
	}
	if c.ProbeConcurrency <= 0 {
		c.ProbeConcurrency = 16
	}
	if c.MaxProbeTargets <= 0 {
		c.MaxProbeTargets = 1024
	}
	if c.DBDialTimeout <= 0 {
		c.DBDialTimeout = 10 * time.Second
	}
	if c.SweepInterval <= 0 {
		c.SweepInterval = 6 * time.Hour
	}
	return c
}

// AgentDialer opens a TCP stream to a target address THROUGH a specific
// outbound agent. The broker Relay satisfies it (DialThroughAgent). The agent
// sweep depends only on this seam so it never reaches into the broker internals
// and stays unit-testable with a fake dialer.
type AgentDialer interface {
	DialThroughAgent(ctx context.Context, workspaceID, agentID uuid.UUID, targetAddr string) (net.Conn, error)
}

// DialBudgeter is an optional capability an AgentDialer may advertise to widen
// the outer per-probe dial deadline beyond ProbeTimeout. A direct dialer does
// not implement it, so probeOne keeps the tight 3s probe timeout. The
// cross-replica forward-only dialer does implement it (returning ForwardTimeout)
// because its dial is multi-hop — a directory lookup, an owner-replica TCP+mTLS
// handshake, a forward request/response, and the agent-side dial — and so needs
// a wider budget than a single direct probe. probeOne uses the advertised
// budget, when positive, as the outer dial deadline; otherwise ProbeTimeout.
type DialBudgeter interface {
	DialBudget() time.Duration
}

// AgentBinder binds a freshly-onboarded PAM target to an outbound agent
// (via_agent_id). The broker AgentDirectory satisfies it. Onboarding depends on
// this seam so an asset found through an agent can be onboarded pre-bound to
// that agent in one step.
type AgentBinder interface {
	BindTarget(ctx context.Context, workspaceID, agentID, targetID uuid.UUID, actor string) error
}

// ConnectorResolver turns a workspace's connector id into a ready-to-call
// connector with decrypted config/secrets. lifecycle.DBConnectorResolver
// satisfies it; reused here so discovery does not duplicate secret-unsealing.
type ConnectorResolver interface {
	Resolve(ctx context.Context, workspaceID, connectorID uuid.UUID) (*lifecycle.ResolvedConnector, error)
}

// Engine is the discovery service: it owns the three sources, the reconciler,
// the onboarding/policy logic, and the read surface. All reads and writes are
// workspace-scoped; mutations append to the per-workspace audit hash chain.
type Engine struct {
	db       *gorm.DB
	vault    *pam.Vault
	enc      access.CredentialEncryptor
	resolver ConnectorResolver
	dialer   AgentDialer
	binder   AgentBinder
	dbEnum   DBEnumerator
	cfg      Config
	now      func() time.Time
}

// NewEngine wires the engine. db and vault are required; the other seams are
// optional and gate the corresponding source/capability when nil (a sweep
// against a missing seam returns ErrUnsupported rather than panicking), which
// keeps a degraded boot fail-open.
func NewEngine(db *gorm.DB, vault *pam.Vault, opts ...Option) *Engine {
	e := &Engine{
		db:     db,
		vault:  vault,
		cfg:    Config{}.withDefaults(),
		now:    time.Now,
		dbEnum: defaultDBEnumerator{},
	}
	for _, opt := range opts {
		opt(e)
	}
	e.cfg = e.cfg.withDefaults()
	return e
}

// Option configures an Engine.
type Option func(*Engine)

// WithConfig sets the tuning config.
func WithConfig(c Config) Option { return func(e *Engine) { e.cfg = c } }

// WithEncryptor sets the credential encryptor used to seal auto-onboarding
// policy credentials.
func WithEncryptor(enc access.CredentialEncryptor) Option {
	return func(e *Engine) { e.enc = enc }
}

// WithConnectorResolver enables the connector-inventory source.
func WithConnectorResolver(r ConnectorResolver) Option {
	return func(e *Engine) { e.resolver = r }
}

// WithDialer enables the agent network sweep source.
func WithDialer(d AgentDialer) Option { return func(e *Engine) { e.dialer = d } }

// WithBinder enables pre-binding an onboarded target to its agent.
func WithBinder(b AgentBinder) Option { return func(e *Engine) { e.binder = b } }

// WithDBEnumerator overrides the DB account enumerator (tests inject a fake).
func WithDBEnumerator(d DBEnumerator) Option {
	return func(e *Engine) {
		if d != nil {
			e.dbEnum = d
		}
	}
}

// WithClock overrides the time source (tests).
func WithClock(now func() time.Time) Option {
	return func(e *Engine) {
		if now != nil {
			e.now = now
		}
	}
}

// --- Read surface ---------------------------------------------------------

// AssetFilter narrows an asset listing. Empty fields do not filter.
type AssetFilter struct {
	Source   string
	Protocol string
	Status   string
	Limit    int
}

// ListAssets returns a workspace's discovered assets, newest-seen first,
// applying the optional facet filters. Limit is clamped to [1,500] (default
// 200) so a tenant listing never scans unbounded rows.
func (e *Engine) ListAssets(ctx context.Context, workspaceID uuid.UUID, f AssetFilter) ([]models.DiscoveredAsset, error) {
	if workspaceID == uuid.Nil {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	q := e.db.WithContext(ctx).Where("workspace_id = ?", workspaceID)
	if f.Source != "" {
		q = q.Where("source = ?", f.Source)
	}
	if f.Protocol != "" {
		q = q.Where("protocol = ?", f.Protocol)
	}
	if f.Status != "" {
		q = q.Where("status = ?", f.Status)
	}
	limit := clampLimit(f.Limit)
	var rows []models.DiscoveredAsset
	if err := q.Order("last_seen_at DESC").Limit(limit).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("discovery: list assets: %w", err)
	}
	return rows, nil
}

// GetAsset loads one asset by id, scoped to the workspace.
func (e *Engine) GetAsset(ctx context.Context, workspaceID, id uuid.UUID) (*models.DiscoveredAsset, error) {
	if workspaceID == uuid.Nil || id == uuid.Nil {
		return nil, fmt.Errorf("%w: workspace_id and id are required", ErrValidation)
	}
	var row models.DiscoveredAsset
	if err := e.db.WithContext(ctx).Where("workspace_id = ? AND id = ?", workspaceID, id).Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("discovery: get asset: %w", err)
	}
	return &row, nil
}

// ListAccounts returns discovered DB accounts for a workspace, optionally
// filtered to one target.
func (e *Engine) ListAccounts(ctx context.Context, workspaceID uuid.UUID, targetID *uuid.UUID, limit int) ([]models.DiscoveredAccount, error) {
	if workspaceID == uuid.Nil {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	q := e.db.WithContext(ctx).Where("workspace_id = ?", workspaceID)
	if targetID != nil && *targetID != uuid.Nil {
		q = q.Where("target_id = ?", *targetID)
	}
	var rows []models.DiscoveredAccount
	if err := q.Order("last_seen_at DESC").Limit(clampLimit(limit)).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("discovery: list accounts: %w", err)
	}
	return rows, nil
}

// ListScans returns a workspace's recent discovery scans, newest first.
func (e *Engine) ListScans(ctx context.Context, workspaceID uuid.UUID, limit int) ([]models.DiscoveryScan, error) {
	if workspaceID == uuid.Nil {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	var rows []models.DiscoveryScan
	if err := e.db.WithContext(ctx).
		Where("workspace_id = ?", workspaceID).
		Order("started_at DESC").Limit(clampLimit(limit)).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("discovery: list scans: %w", err)
	}
	return rows, nil
}

// InventorySummary is the aggregate count surface the UI stat cards render.
type InventorySummary struct {
	TotalAssets     int64 `json:"total_assets"`
	UnmanagedAssets int64 `json:"unmanaged_assets"`
	ManagedAssets   int64 `json:"managed_assets"`
	OrphanAccounts  int64 `json:"orphan_accounts"`
	RecommendedNow  int64 `json:"recommended_now"`
}

// Summary returns the per-workspace aggregate counts in one round of cheap
// COUNT queries (each served by the workspace/status index).
func (e *Engine) Summary(ctx context.Context, workspaceID uuid.UUID) (InventorySummary, error) {
	if workspaceID == uuid.Nil {
		return InventorySummary{}, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	var s InventorySummary
	base := e.db.WithContext(ctx).Model(&models.DiscoveredAsset{}).Where("workspace_id = ?", workspaceID)
	if err := base.Session(&gorm.Session{}).Count(&s.TotalAssets).Error; err != nil {
		return s, fmt.Errorf("discovery: count assets: %w", err)
	}
	if err := base.Session(&gorm.Session{}).Where("status = ?", models.DiscoveryStatusUnmanaged).Count(&s.UnmanagedAssets).Error; err != nil {
		return s, fmt.Errorf("discovery: count unmanaged: %w", err)
	}
	if err := base.Session(&gorm.Session{}).Where("status = ?", models.DiscoveryStatusManaged).Count(&s.ManagedAssets).Error; err != nil {
		return s, fmt.Errorf("discovery: count managed: %w", err)
	}
	if err := base.Session(&gorm.Session{}).Where("policy_matched = ? AND status = ?", true, models.DiscoveryStatusUnmanaged).Count(&s.RecommendedNow).Error; err != nil {
		return s, fmt.Errorf("discovery: count recommended: %w", err)
	}
	if err := e.db.WithContext(ctx).Model(&models.DiscoveredAccount{}).
		Where("workspace_id = ? AND status = ?", workspaceID, models.DiscoveryStatusOrphan).
		Count(&s.OrphanAccounts).Error; err != nil {
		return s, fmt.Errorf("discovery: count orphan accounts: %w", err)
	}
	return s, nil
}

func clampLimit(n int) int {
	const def, max = 200, 500
	if n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

// appendAudit records a discovery mutation on the workspace's audit hash chain
// in its own transaction. State-mutating helpers that already run inside a
// transaction use lifecycle.AppendAuditTx directly so the change and its audit
// row commit atomically.
func (e *Engine) appendAudit(ctx context.Context, workspaceID uuid.UUID, actor, action, targetRef string, meta map[string]any) error {
	return lifecycle.AppendAudit(ctx, e.db, e.now(), lifecycle.AuditInput{
		WorkspaceID: workspaceID,
		Actor:       actor,
		Action:      action,
		TargetRef:   targetRef,
		Metadata:    mustAuditMeta(meta),
	})
}
