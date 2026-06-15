package pam

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
)

// Dynamic (ephemeral) database credentials.
//
// This is the database analogue of the SSH CA's ephemeral per-session
// certificate (internal/gateway/ssh_ca.go): instead of handing a long-lived
// stored password to a JIT session, a target with dynamic credentials enabled
// mints a short-lived database role scoped to the lease and drops it at
// checkin/expiry. The minted role's password is returned to the caller exactly
// once and is never persisted — only the role's lifecycle is tracked so the
// reaper can drop it upstream when the lease ends or its TTL lapses.

// ErrDynamicNotEnabled is returned when a dynamic credential is requested for a
// target whose policy does not enable dynamic credentials.
var ErrDynamicNotEnabled = errors.New("pam: dynamic credentials not enabled for target")

// ErrDynamicUnsupported is returned for a protocol that cannot mint dynamic
// credentials (only PostgreSQL and MySQL can).
var ErrDynamicUnsupported = errors.New("pam: dynamic credentials not supported for protocol")

// defaultDynamicTTL bounds an ephemeral credential when a policy enables dynamic
// credentials without an explicit TTL.
const defaultDynamicTTL = time.Hour

// dynamicUserPrefix namespaces every minted role so an operator can recognise
// (and an emergency script can sweep) credentials this product created. Kept
// short so the full name fits MySQL's 32-char username limit.
const dynamicUserPrefix = "sng_dyn_"

// MintedCredential is the one-time result of minting a dynamic credential. The
// password is present only here and is never stored.
type MintedCredential struct {
	ID        uuid.UUID `json:"id"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	Protocol  string    `json:"protocol"`
	ExpiresAt time.Time `json:"expires_at"`
}

// dbCredentialProvisioner performs the upstream side of a dynamic credential:
// creating and dropping the ephemeral DB role. The live implementation talks
// real SQL; tests inject a fake so the DB-state lifecycle can be exercised
// without a running database (the same seam the rotation executors use).
type dbCredentialProvisioner interface {
	Create(ctx context.Context, target *models.PAMTarget, admin Secret, username, password string, expires time.Time) error
	Drop(ctx context.Context, target *models.PAMTarget, admin Secret, username string) error
}

// DynamicCredentialService mints and reaps ephemeral database credentials.
type DynamicCredentialService struct {
	db    *gorm.DB
	vault *Vault
	prov  dbCredentialProvisioner
	now   func() time.Time
}

// NewDynamicCredentialService wires the service. dialTimeout bounds every
// upstream connection (defaults to 10s).
func NewDynamicCredentialService(db *gorm.DB, vault *Vault, dialTimeout time.Duration) *DynamicCredentialService {
	if dialTimeout <= 0 {
		dialTimeout = 10 * time.Second
	}
	return &DynamicCredentialService{db: db, vault: vault, prov: &liveDBProvisioner{dialTimeout: dialTimeout}, now: time.Now}
}

// withProvisioner swaps the upstream provisioner (tests).
func (s *DynamicCredentialService) withProvisioner(p dbCredentialProvisioner) *DynamicCredentialService {
	if p != nil {
		s.prov = p
	}
	return s
}

// SetClock overrides the time source (tests).
func (s *DynamicCredentialService) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// SupportsProtocol reports whether dynamic credentials can be minted for a
// protocol.
func (s *DynamicCredentialService) SupportsProtocol(protocol string) bool {
	return protocol == models.PAMProtocolPostgres || protocol == models.PAMProtocolMySQL
}

// MintForLease mints an ephemeral credential bound to a live JIT lease and
// returns it once. The caller (handler) is responsible for confirming the lease
// is live before calling. The credential is dropped by the reaper when the
// lease ends or the TTL lapses.
func (s *DynamicCredentialService) MintForLease(ctx context.Context, workspaceID, targetID, leaseID uuid.UUID, actor string) (*MintedCredential, error) {
	if workspaceID == uuid.Nil || targetID == uuid.Nil || leaseID == uuid.Nil {
		return nil, fmt.Errorf("%w: workspace_id, target_id and lease_id are required", ErrValidation)
	}
	target, err := s.vault.GetTarget(ctx, workspaceID, targetID)
	if err != nil {
		return nil, err
	}
	if !s.SupportsProtocol(target.Protocol) {
		return nil, fmt.Errorf("%w: %q", ErrDynamicUnsupported, target.Protocol)
	}
	policy, err := s.loadPolicy(ctx, workspaceID, targetID)
	if err != nil {
		return nil, err
	}
	if policy == nil || !policy.DynamicEnabled {
		return nil, ErrDynamicNotEnabled
	}
	ttl := policy.DynamicTTL()
	if ttl <= 0 {
		ttl = defaultDynamicTTL
	}

	admin, err := s.vault.OpenSecret(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("pam: open admin secret: %w", err)
	}
	username, err := dynamicUsername()
	if err != nil {
		return nil, err
	}
	password, err := generatePassword(32)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	expires := now.Add(ttl)

	// Record the credential as active BEFORE creating it upstream so a crash
	// between the upstream create and the DB insert can never orphan a role the
	// reaper doesn't know about. If the upstream create then fails we mark the
	// row failed (the reaper will attempt a drop anyway, which is a harmless
	// no-op when the role was never created).
	cred := &models.DynamicCredential{
		WorkspaceID: workspaceID,
		TargetID:    targetID,
		LeaseID:     &leaseID,
		Protocol:    target.Protocol,
		DBUsername:  username,
		State:       models.DynamicCredentialStateActive,
		ExpiresAt:   &expires,
	}
	if err := s.db.WithContext(ctx).Create(cred).Error; err != nil {
		return nil, fmt.Errorf("pam: record dynamic credential: %w", err)
	}

	if err := s.prov.Create(ctx, target, admin, username, password, expires); err != nil {
		s.markFailed(ctx, cred.ID, err)
		return nil, err
	}

	if aerr := s.vault.audit(ctx, workspaceID, actor, "pam.dynamic_credential.minted", targetID.String(), map[string]any{
		"lease_id":   leaseID.String(),
		"db_username": username,
		"protocol":   target.Protocol,
		"expires_at": expires.Format(time.RFC3339),
	}); aerr != nil {
		logger.Warnf(ctx, "pam: audit dynamic credential mint: %v", aerr)
	}

	return &MintedCredential{
		ID:        cred.ID,
		Username:  username,
		Password:  password,
		Protocol:  target.Protocol,
		ExpiresAt: expires,
	}, nil
}

// ReapDue drops every active credential whose lease is no longer live or whose
// TTL has lapsed, marking each terminal in the DB. Set-based selection over the
// active partial index keeps the sweep O(due rows). Fail-open per row: one bad
// drop never starves the rest.
func (s *DynamicCredentialService) ReapDue(ctx context.Context) (int, error) {
	now := s.now().UTC()
	var due []models.DynamicCredential
	// A credential is due when its TTL lapsed OR its owning lease is no longer
	// live (ended/revoked). The lease liveness check is a correlated NOT EXISTS
	// over the live set.
	if err := s.db.WithContext(ctx).
		Where(`state = ? AND deleted_at IS NULL AND (
			(expires_at IS NOT NULL AND expires_at <= ?)
			OR (lease_id IS NOT NULL AND NOT EXISTS (
				SELECT 1 FROM pam_leases l
				WHERE l.id = pam_dynamic_credentials.lease_id
				  AND l.granted_at IS NOT NULL AND l.revoked_at IS NULL
				  AND (l.expires_at IS NULL OR l.expires_at > ?)
			))
		)`, models.DynamicCredentialStateActive, now, now).
		Find(&due).Error; err != nil {
		return 0, fmt.Errorf("pam: select due dynamic credentials: %w", err)
	}

	reaped := 0
	for i := range due {
		cred := &due[i]
		if err := s.dropOne(ctx, cred, now); err != nil {
			logger.Warnf(ctx, "pam: reap dynamic credential %s: %v", cred.ID, err)
			continue
		}
		reaped++
	}
	return reaped, nil
}

// RevokeForLease drops every active credential bound to a lease (used when a
// lease is revoked/checked in explicitly rather than waiting for the sweep).
func (s *DynamicCredentialService) RevokeForLease(ctx context.Context, workspaceID, leaseID uuid.UUID) (int, error) {
	if workspaceID == uuid.Nil || leaseID == uuid.Nil {
		return 0, fmt.Errorf("%w: workspace_id and lease_id are required", ErrValidation)
	}
	now := s.now().UTC()
	var creds []models.DynamicCredential
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND lease_id = ? AND state = ? AND deleted_at IS NULL",
			workspaceID, leaseID, models.DynamicCredentialStateActive).
		Find(&creds).Error; err != nil {
		return 0, fmt.Errorf("pam: select lease dynamic credentials: %w", err)
	}
	revoked := 0
	for i := range creds {
		if err := s.dropOne(ctx, &creds[i], now); err != nil {
			logger.Warnf(ctx, "pam: revoke dynamic credential %s: %v", creds[i].ID, err)
			continue
		}
		revoked++
	}
	return revoked, nil
}

// dropOne drops a single credential's upstream role and marks the row terminal.
func (s *DynamicCredentialService) dropOne(ctx context.Context, cred *models.DynamicCredential, now time.Time) error {
	target, err := s.vault.GetTarget(ctx, cred.WorkspaceID, cred.TargetID)
	if err != nil {
		return fmt.Errorf("load target: %w", err)
	}
	admin, err := s.vault.OpenSecret(ctx, target)
	if err != nil {
		return fmt.Errorf("open admin secret: %w", err)
	}
	if err := s.prov.Drop(ctx, target, admin, cred.DBUsername); err != nil {
		return fmt.Errorf("drop upstream role: %w", err)
	}
	state := models.DynamicCredentialStateExpired
	if cred.ExpiresAt == nil || cred.ExpiresAt.After(now) {
		// Dropped before its TTL — the lease ended.
		state = models.DynamicCredentialStateRevoked
	}
	if err := s.db.WithContext(ctx).
		Model(&models.DynamicCredential{}).
		Where("id = ?", cred.ID).
		Updates(map[string]any{
			"state":      state,
			"revoked_at": now,
			"updated_at": now,
			"last_error": "",
		}).Error; err != nil {
		return fmt.Errorf("mark credential terminal: %w", err)
	}
	if aerr := s.vault.audit(ctx, cred.WorkspaceID, "rotation-scheduler", "pam.dynamic_credential.dropped", cred.TargetID.String(), map[string]any{
		"db_username": cred.DBUsername,
		"state":       state,
	}); aerr != nil {
		logger.Warnf(ctx, "pam: audit dynamic credential drop: %v", aerr)
	}
	return nil
}

func (s *DynamicCredentialService) markFailed(ctx context.Context, id uuid.UUID, cause error) {
	if err := s.db.WithContext(ctx).
		Model(&models.DynamicCredential{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"state":      models.DynamicCredentialStateFailed,
			"last_error": truncateError(cause.Error()),
			"updated_at": s.now().UTC(),
		}).Error; err != nil {
		logger.Warnf(ctx, "pam: mark dynamic credential %s failed: %v", id, err)
	}
}

func (s *DynamicCredentialService) loadPolicy(ctx context.Context, workspaceID, targetID uuid.UUID) (*models.RotationPolicy, error) {
	var p models.RotationPolicy
	err := s.db.WithContext(ctx).
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

// ---------------------------------------------------------------------------
// Upstream create/drop
// ---------------------------------------------------------------------------

// liveDBProvisioner is the production provisioner: it creates and drops the
// ephemeral role over a real SQL connection to the upstream database.
type liveDBProvisioner struct {
	dialTimeout time.Duration
}

// Create creates the ephemeral login role on the upstream database and grants
// it the membership configured on the target (Config["dynamic_grant_role"] for
// PostgreSQL; Config["dynamic_grant"] privilege spec for MySQL).
func (s *liveDBProvisioner) Create(ctx context.Context, target *models.PAMTarget, admin Secret, username, password string, expires time.Time) error {
	switch target.Protocol {
	case models.PAMProtocolPostgres:
		return s.createPostgres(ctx, target, admin, username, password, expires)
	case models.PAMProtocolMySQL:
		return s.createMySQL(ctx, target, admin, username, password)
	default:
		return fmt.Errorf("%w: %q", ErrDynamicUnsupported, target.Protocol)
	}
}

// Drop drops the ephemeral role from the upstream database.
func (s *liveDBProvisioner) Drop(ctx context.Context, target *models.PAMTarget, admin Secret, username string) error {
	switch target.Protocol {
	case models.PAMProtocolPostgres:
		return s.dropPostgres(ctx, target, admin, username)
	case models.PAMProtocolMySQL:
		return s.dropMySQL(ctx, target, admin, username)
	default:
		return fmt.Errorf("%w: %q", ErrDynamicUnsupported, target.Protocol)
	}
}

func (s *liveDBProvisioner) createPostgres(ctx context.Context, target *models.PAMTarget, admin Secret, username, password string, expires time.Time) error {
	ep, err := resolveDBEndpoint(target, admin, 5432)
	if err != nil {
		return err
	}
	conn, err := pgConnect(ctx, ep, admin.Password, s.dialTimeout)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(context.Background()) }()

	ident := pgIdentifier(username)
	stmt := fmt.Sprintf("CREATE ROLE %s WITH LOGIN PASSWORD %s VALID UNTIL %s",
		ident, quoteSQLLiteral(password), quoteSQLLiteral(expires.Format("2006-01-02 15:04:05-07")))
	if _, err := conn.Exec(ctx, stmt); err != nil {
		return fmt.Errorf("pam: pg create ephemeral role: %w", err)
	}
	if role := strings.TrimSpace(decodeConfig(target.Config)["dynamic_grant_role"]); role != "" {
		if _, err := conn.Exec(ctx, fmt.Sprintf("GRANT %s TO %s", pgIdentifier(role), ident)); err != nil {
			return fmt.Errorf("pam: pg grant role membership: %w", err)
		}
	}
	return nil
}

func (s *liveDBProvisioner) dropPostgres(ctx context.Context, target *models.PAMTarget, admin Secret, username string) error {
	ep, err := resolveDBEndpoint(target, admin, 5432)
	if err != nil {
		return err
	}
	conn, err := pgConnect(ctx, ep, admin.Password, s.dialTimeout)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(context.Background()) }()
	ident := pgIdentifier(username)
	// DROP OWNED first so any default-privilege grants are removed; harmless when
	// the ephemeral role owns nothing.
	_, _ = conn.Exec(ctx, fmt.Sprintf("DROP OWNED BY %s", ident))
	if _, err := conn.Exec(ctx, fmt.Sprintf("DROP ROLE IF EXISTS %s", ident)); err != nil {
		return fmt.Errorf("pam: pg drop ephemeral role: %w", err)
	}
	return nil
}

func (s *liveDBProvisioner) createMySQL(ctx context.Context, target *models.PAMTarget, admin Secret, username, password string) error {
	ep, err := resolveDBEndpoint(target, admin, 3306)
	if err != nil {
		return err
	}
	db, err := mysqlOpen(ep, admin.Password, s.dialTimeout)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	host := mysqlAccountHost(target)
	if _, err := db.ExecContext(ctx, fmt.Sprintf("CREATE USER %s@%s IDENTIFIED BY %s",
		mysqlQuoteLiteral(username), mysqlQuoteLiteral(host), mysqlQuoteLiteral(password))); err != nil {
		return fmt.Errorf("pam: mysql create ephemeral user: %w", err)
	}
	if grant := strings.TrimSpace(decodeConfig(target.Config)["dynamic_grant"]); grant != "" {
		// grant is an operator-configured privilege spec, e.g. "SELECT ON app.*".
		if _, err := db.ExecContext(ctx, fmt.Sprintf("GRANT %s TO %s@%s",
			grant, mysqlQuoteLiteral(username), mysqlQuoteLiteral(host))); err != nil {
			return fmt.Errorf("pam: mysql grant: %w", err)
		}
	}
	return nil
}

func (s *liveDBProvisioner) dropMySQL(ctx context.Context, target *models.PAMTarget, admin Secret, username string) error {
	ep, err := resolveDBEndpoint(target, admin, 3306)
	if err != nil {
		return err
	}
	db, err := mysqlOpen(ep, admin.Password, s.dialTimeout)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	host := mysqlAccountHost(target)
	if _, err := db.ExecContext(ctx, fmt.Sprintf("DROP USER IF EXISTS %s@%s",
		mysqlQuoteLiteral(username), mysqlQuoteLiteral(host))); err != nil {
		return fmt.Errorf("pam: mysql drop ephemeral user: %w", err)
	}
	return nil
}

// dynamicUsername returns a fresh ephemeral DB username (prefix + 12 lowercase
// alphanumerics), short enough for MySQL's 32-char username limit.
func dynamicUsername() (string, error) {
	const suffixLen = 12
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	buf := make([]byte, suffixLen)
	max := big.NewInt(int64(len(alphabet)))
	for i := range buf {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("pam: generate dynamic username: %w", err)
		}
		buf[i] = alphabet[idx.Int64()]
	}
	return dynamicUserPrefix + string(buf), nil
}
