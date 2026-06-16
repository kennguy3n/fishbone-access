package discovery

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// EnumeratedAccount is one DB-internal role/user returned by a DBEnumerator.
type EnumeratedAccount struct {
	Username   string
	CanLogin   bool
	Superuser  bool
	Attributes map[string]string
}

// DBEnumerator lists the DB-internal roles/users on a database endpoint using
// the supplied admin credential. The engine depends on this seam so the account
// source is unit-testable with a fake and the production impl (pgx / database-sql)
// is swapped in transparently. Implementations MUST honour ctx and never log the
// password.
type DBEnumerator interface {
	Enumerate(ctx context.Context, protocol, address, username, password string, timeout time.Duration) ([]EnumeratedAccount, error)
}

// EnumerateAccounts enumerates the DB-internal accounts on an already-registered
// PAM database target and reconciles them into the discovered-account surface,
// classifying each managed/unmanaged/orphan against the target's live grants.
// The admin credential is opened from the vault and never leaves this call.
func (e *Engine) EnumerateAccounts(ctx context.Context, workspaceID, targetID uuid.UUID, actor, trigger string) (AccountScanResult, error) {
	if workspaceID == uuid.Nil || targetID == uuid.Nil {
		return AccountScanResult{}, fmt.Errorf("%w: workspace_id and target_id are required", ErrValidation)
	}
	target, err := e.vault.GetTarget(ctx, workspaceID, targetID)
	if err != nil {
		if errors.Is(err, gormErrNotFound) {
			return AccountScanResult{}, ErrNotFound
		}
		return AccountScanResult{}, fmt.Errorf("discovery: load target: %w", err)
	}
	if !isDatabaseProtocol(target.Protocol) {
		return AccountScanResult{}, fmt.Errorf("%w: target protocol %q is not a database", ErrUnsupported, target.Protocol)
	}

	secret, err := e.vault.OpenSecret(ctx, target)
	if err != nil {
		return AccountScanResult{}, fmt.Errorf("discovery: open target secret: %w", err)
	}
	username := target.Username
	if username == "" {
		username = secret.Username
	}

	if trigger == "" {
		trigger = models.DiscoveryTriggerManual
	}
	scan, err := e.startScan(ctx, workspaceID, models.DiscoverySourceDBAccounts, trigger, actor, map[string]any{
		"target_id": targetID.String(),
		"protocol":  target.Protocol,
	})
	if err != nil {
		return AccountScanResult{}, err
	}

	result := AccountScanResult{ScanID: scan.ID}
	accounts, encErr := e.dbEnum.Enumerate(ctx, target.Protocol, target.Address, username, secret.Password, e.cfg.DBDialTimeout)
	if encErr != nil {
		e.finishScan(ctx, scan, encErr)
		return result, fmt.Errorf("discovery: enumerate accounts: %w", encErr)
	}

	managed, err := e.managedDBUsernames(ctx, workspaceID, target.Address)
	if err != nil {
		e.finishScan(ctx, scan, err)
		return result, err
	}
	found, recErr := e.reconcileAccounts(ctx, workspaceID, targetID, accounts, managed)
	result.AccountsFound = found
	scan.AccountsFound = found
	e.finishScan(ctx, scan, recErr)
	if recErr != nil {
		return result, recErr
	}
	if err := e.appendAudit(ctx, workspaceID, actor, "discovery.db_accounts", targetID.String(), map[string]any{
		"protocol":       target.Protocol,
		"accounts_found": found,
		"scan_id":        scan.ID.String(),
	}); err != nil {
		return result, err
	}
	return result, nil
}

// AccountScanResult summarises a DB account-enumeration scan.
type AccountScanResult struct {
	ScanID        uuid.UUID `json:"scan_id"`
	AccountsFound int       `json:"accounts_found"`
}

// managedDBUsernames returns the set of DB usernames ShieldNet already manages a
// credential for at this database endpoint: the Username of every PAM target in
// the workspace whose Address matches. A discovered account matching one of
// these is classified managed; a login-capable account that does NOT is an
// orphan (privileged access ShieldNet is not yet governing).
func (e *Engine) managedDBUsernames(ctx context.Context, workspaceID uuid.UUID, address string) (map[string]struct{}, error) {
	var usernames []string
	if err := e.db.WithContext(ctx).Model(&models.PAMTarget{}).
		Where("workspace_id = ? AND address = ?", workspaceID, address).
		Distinct().Pluck("username", &usernames).Error; err != nil {
		return nil, fmt.Errorf("discovery: load managed target usernames: %w", err)
	}
	set := make(map[string]struct{}, len(usernames))
	for _, u := range usernames {
		if u != "" {
			set[u] = struct{}{}
		}
	}
	return set, nil
}

func isDatabaseProtocol(protocol string) bool {
	switch protocol {
	case models.PAMProtocolPostgres, models.PAMProtocolMySQL:
		return true
	default:
		return false
	}
}

// gormErrNotFound is an alias kept local so db_accounts.go does not import gorm
// just for the sentinel; the vault returns it directly.
var gormErrNotFound = pam.ErrTargetNotFound

// ---------------------------------------------------------------------------
// Production DBEnumerator
// ---------------------------------------------------------------------------

// defaultDBEnumerator is the production enumerator. It connects to the database
// with the admin credential (TLS negotiated, sslmode=prefer-equivalent) and runs
// a single read-only catalogue query, mirroring the gateway/rotation dial
// conventions. It opens no long-lived pool: one short connection per scan.
type defaultDBEnumerator struct{}

func (defaultDBEnumerator) Enumerate(ctx context.Context, protocol, address, username, password string, timeout time.Duration) ([]EnumeratedAccount, error) {
	switch protocol {
	case models.PAMProtocolPostgres:
		return enumeratePostgres(ctx, address, username, password, timeout)
	case models.PAMProtocolMySQL:
		return enumerateMySQL(ctx, address, username, password, timeout)
	default:
		return nil, fmt.Errorf("%w: protocol %q cannot enumerate accounts", ErrUnsupported, protocol)
	}
}

func splitAddr(address string, defaultPort uint16) (host string, port uint16, err error) {
	h, portStr, splitErr := net.SplitHostPort(strings.TrimSpace(address))
	if splitErr != nil {
		h = strings.TrimSpace(address)
		portStr = ""
	}
	if h == "" {
		return "", 0, fmt.Errorf("%w: target address is empty", ErrValidation)
	}
	port = defaultPort
	if portStr != "" {
		p, perr := strconv.ParseUint(portStr, 10, 16)
		if perr != nil {
			return "", 0, fmt.Errorf("%w: invalid port %q", ErrValidation, portStr)
		}
		port = uint16(p)
	}
	return h, port, nil
}

func enumeratePostgres(ctx context.Context, address, username, password string, timeout time.Duration) ([]EnumeratedAccount, error) {
	host, port, err := splitAddr(address, 5432)
	if err != nil {
		return nil, err
	}
	cfg, err := pgx.ParseConfig("")
	if err != nil {
		return nil, fmt.Errorf("discovery: pg base config: %w", err)
	}
	cfg.Host = host
	cfg.Port = port
	cfg.User = username
	cfg.Password = password
	// The bootstrap "postgres" database is present on every server and avoids
	// depending on a database named after the admin role.
	cfg.Database = "postgres"
	cfg.ConnectTimeout = timeout
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := pgx.ConnectConfig(dialCtx, cfg)
	if err != nil {
		return nil, fmt.Errorf("discovery: pg connect %s:%d: %w", host, port, err)
	}
	defer func() { _ = conn.Close(context.Background()) }()

	queryCtx, qcancel := context.WithTimeout(ctx, timeout)
	defer qcancel()
	rows, err := conn.Query(queryCtx, "SELECT rolname, rolcanlogin, rolsuper, rolcreaterole, rolreplication FROM pg_roles ORDER BY rolname")
	if err != nil {
		return nil, fmt.Errorf("discovery: pg query roles: %w", err)
	}
	defer rows.Close()
	var out []EnumeratedAccount
	for rows.Next() {
		var (
			name                                     string
			canLogin, super, createRole, replication bool
		)
		if err := rows.Scan(&name, &canLogin, &super, &createRole, &replication); err != nil {
			return nil, fmt.Errorf("discovery: pg scan role: %w", err)
		}
		out = append(out, EnumeratedAccount{
			Username:  name,
			CanLogin:  canLogin,
			Superuser: super,
			Attributes: map[string]string{
				"createrole":  strconv.FormatBool(createRole),
				"replication": strconv.FormatBool(replication),
			},
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("discovery: pg rows: %w", err)
	}
	return out, nil
}

func enumerateMySQL(ctx context.Context, address, username, password string, timeout time.Duration) ([]EnumeratedAccount, error) {
	host, port, err := splitAddr(address, 3306)
	if err != nil {
		return nil, err
	}
	cfg := mysql.NewConfig()
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(host, strconv.Itoa(int(port)))
	cfg.User = username
	cfg.Passwd = password
	cfg.DBName = "mysql"
	cfg.Timeout = timeout
	cfg.ReadTimeout = timeout
	cfg.WriteTimeout = timeout
	cfg.TLSConfig = "preferred"
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return nil, fmt.Errorf("discovery: mysql open: %w", err)
	}
	db.SetConnMaxLifetime(2 * timeout)
	db.SetMaxOpenConns(1)
	defer func() { _ = db.Close() }()

	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// account_locked / Super_priv exist on MySQL 5.7.6+ and MariaDB 10.4.2+; the
	// query is read-only and depends only on long-stable mysql.user columns.
	rows, err := db.QueryContext(queryCtx, "SELECT User, Host, Super_priv, account_locked FROM mysql.user ORDER BY User, Host")
	if err != nil {
		// On legacy servers (MySQL <5.7.6, MariaDB <10.4.2) account_locked is
		// absent, which the driver reports as ER_BAD_FIELD_ERROR (1054). Map it
		// to a clear, actionable message so a non-expert SME operator sees
		// "unsupported version" rather than an opaque SQL column error.
		var myErr *mysql.MySQLError
		if errors.As(err, &myErr) && myErr.Number == 1054 {
			return nil, fmt.Errorf("%w: DB account enumeration requires MySQL 5.7.6+ or MariaDB 10.4.2+ (this server is missing the mysql.user.account_locked column)", ErrUnsupported)
		}
		return nil, fmt.Errorf("discovery: mysql query users: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []EnumeratedAccount
	for rows.Next() {
		var user, host, superPriv, locked string
		if err := rows.Scan(&user, &host, &superPriv, &locked); err != nil {
			return nil, fmt.Errorf("discovery: mysql scan user: %w", err)
		}
		out = append(out, EnumeratedAccount{
			Username:  user,
			CanLogin:  !strings.EqualFold(locked, "Y"),
			Superuser: strings.EqualFold(superPriv, "Y"),
			Attributes: map[string]string{
				"host":           host,
				"account_locked": locked,
			},
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("discovery: mysql rows: %w", err)
	}
	return out, nil
}
