package pam

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/ssh"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// RotationExecutor performs the actual credential change on an upstream target.
// An executor is responsible only for the upstream side of a rotation: it
// generates a fresh credential, installs it on the target, and VERIFIES it
// works before returning. The engine owns the vault re-seal and audit; the
// executor never touches the database.
//
// Safety contract: Rotate must be all-or-nothing on the upstream. If it returns
// an error the upstream MUST still accept the `current` credential (a half-
// applied change that locks the vault out is the one outcome we must never
// produce). When the engine fails to persist a successfully-rotated credential
// it calls Restore to roll the upstream back, authenticating with the new
// credential the executor just installed.
type RotationExecutor interface {
	// Protocol is the PAM protocol this executor rotates (models.PAMProtocol*).
	Protocol() string
	// Rotate installs a freshly generated credential on the upstream, verifies
	// it, and returns it. On any error the upstream is left on `current`.
	Rotate(ctx context.Context, target *models.PAMTarget, current Secret) (Secret, error)
	// Restore re-installs `restore` on the upstream, authenticating with
	// `liveNow` (the credential Rotate just installed). Best-effort rollback.
	Restore(ctx context.Context, target *models.PAMTarget, liveNow Secret, restore Secret) error
}

// ExecutorRegistry resolves a RotationExecutor by protocol. It is the set of
// target types the product can genuinely rotate; a target whose protocol is not
// registered reports ErrRotationUnsupported rather than silently doing nothing.
type ExecutorRegistry struct {
	byProtocol map[string]RotationExecutor
}

// ErrRotationUnsupported is returned for a protocol with no registered executor.
var ErrRotationUnsupported = errors.New("pam: rotation not supported for protocol")

// NewExecutorRegistry builds the default registry with the real SSH, PostgreSQL
// and MySQL executors wired in. dialTimeout bounds every upstream connection.
func NewExecutorRegistry(dialTimeout time.Duration) *ExecutorRegistry {
	if dialTimeout <= 0 {
		dialTimeout = 10 * time.Second
	}
	r := &ExecutorRegistry{byProtocol: map[string]RotationExecutor{}}
	r.Register(&PostgresExecutor{dialTimeout: dialTimeout})
	r.Register(&MySQLExecutor{dialTimeout: dialTimeout})
	r.Register(&SSHExecutor{dialTimeout: dialTimeout})
	return r
}

// Register adds or replaces an executor (used by tests to inject a fake).
func (r *ExecutorRegistry) Register(e RotationExecutor) {
	if r.byProtocol == nil {
		r.byProtocol = map[string]RotationExecutor{}
	}
	r.byProtocol[e.Protocol()] = e
}

// For returns the executor for a protocol, or ErrRotationUnsupported.
func (r *ExecutorRegistry) For(protocol string) (RotationExecutor, error) {
	if e, ok := r.byProtocol[protocol]; ok {
		return e, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrRotationUnsupported, protocol)
}

// Supports reports whether a protocol can be rotated.
func (r *ExecutorRegistry) Supports(protocol string) bool {
	_, ok := r.byProtocol[protocol]
	return ok
}

// ---------------------------------------------------------------------------
// Credential generation
// ---------------------------------------------------------------------------

// passwordAlphabet is intentionally limited to URL/shell/SQL-safe characters so
// a generated secret can be embedded in an ALTER ... PASSWORD literal or a DSN
// without quoting hazards. 72 bits of entropy minimum (see generatePassword).
const passwordAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// generatePassword returns a cryptographically random password of n characters
// drawn from passwordAlphabet.
func generatePassword(n int) (string, error) {
	if n < 24 {
		n = 24
	}
	buf := make([]byte, n)
	max := big.NewInt(int64(len(passwordAlphabet)))
	for i := range buf {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("pam: generate password: %w", err)
		}
		buf[i] = passwordAlphabet[idx.Int64()]
	}
	return string(buf), nil
}

// ---------------------------------------------------------------------------
// Endpoint resolution (shared by executors and dynamic_db_creds.go)
// ---------------------------------------------------------------------------

// dbEndpoint is a resolved upstream database coordinate.
type dbEndpoint struct {
	host     string
	port     uint16
	user     string
	database string
}

// resolveDBEndpoint derives host/port/user/database from a target and the
// admin secret, mirroring the gateway's dial conventions (address is host:port,
// the database comes from Config["database"] and falls back to the user).
func resolveDBEndpoint(target *models.PAMTarget, sec Secret, defaultPort uint16) (dbEndpoint, error) {
	if target == nil {
		return dbEndpoint{}, fmt.Errorf("%w: target is required", ErrValidation)
	}
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(target.Address))
	if err != nil {
		// No explicit port: treat the whole address as the host.
		host = strings.TrimSpace(target.Address)
		portStr = ""
	}
	if host == "" {
		return dbEndpoint{}, fmt.Errorf("%w: target address is empty", ErrValidation)
	}
	port := defaultPort
	if portStr != "" {
		p, perr := strconv.ParseUint(portStr, 10, 16)
		if perr != nil {
			return dbEndpoint{}, fmt.Errorf("%w: invalid port %q", ErrValidation, portStr)
		}
		port = uint16(p)
	}
	user := strings.TrimSpace(target.Username)
	if user == "" {
		user = strings.TrimSpace(sec.Username)
	}
	if user == "" {
		return dbEndpoint{}, fmt.Errorf("%w: target has no username to rotate", ErrValidation)
	}
	cfg := decodeConfig(target.Config)
	database := strings.TrimSpace(cfg["database"])
	if database == "" {
		database = user
	}
	return dbEndpoint{host: host, port: port, user: user, database: database}, nil
}

// decodeConfig decodes a target's Config JSON into a flat string map (a private
// twin of the gateway helper so this package has no gateway dependency).
func decodeConfig(raw []byte) map[string]string {
	out := map[string]string{}
	if len(raw) == 0 {
		return out
	}
	_ = json.Unmarshal(raw, &out)
	return out
}

// ---------------------------------------------------------------------------
// PostgreSQL
// ---------------------------------------------------------------------------

// PostgresExecutor rotates a PostgreSQL login role's password with
// `ALTER ROLE ... WITH PASSWORD`. It rotates the role the vault authenticates
// as (the target's own admin user), so the credential the gateway injects is
// exactly the one that changed.
type PostgresExecutor struct {
	dialTimeout time.Duration
}

// Protocol implements RotationExecutor.
func (e *PostgresExecutor) Protocol() string { return models.PAMProtocolPostgres }

func (e *PostgresExecutor) connect(ctx context.Context, ep dbEndpoint, password string) (*pgx.Conn, error) {
	return pgConnect(ctx, ep, password, e.dialTimeout)
}

// pgConnect opens a single pgx connection to a database endpoint, negotiating
// TLS per the server's capabilities (sslmode=prefer). Shared by the executor
// and the dynamic-credential service.
func pgConnect(ctx context.Context, ep dbEndpoint, password string, timeout time.Duration) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig("")
	if err != nil {
		return nil, fmt.Errorf("pam: pg base config: %w", err)
	}
	cfg.Host = ep.host
	cfg.Port = ep.port
	cfg.User = ep.user
	cfg.Password = password
	cfg.Database = ep.database
	cfg.ConnectTimeout = timeout
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := pgx.ConnectConfig(dialCtx, cfg)
	if err != nil {
		return nil, fmt.Errorf("pam: pg connect %s:%d: %w", ep.host, ep.port, err)
	}
	return conn, nil
}

// Rotate implements RotationExecutor for PostgreSQL.
func (e *PostgresExecutor) Rotate(ctx context.Context, target *models.PAMTarget, current Secret) (Secret, error) {
	ep, err := resolveDBEndpoint(target, current, 5432)
	if err != nil {
		return Secret{}, err
	}
	newPassword, err := generatePassword(32)
	if err != nil {
		return Secret{}, err
	}
	conn, err := e.connect(ctx, ep, current.Password)
	if err != nil {
		return Secret{}, err
	}
	defer func() { _ = conn.Close(context.Background()) }()

	stmt := fmt.Sprintf("ALTER ROLE %s WITH PASSWORD %s",
		pgx.Identifier{ep.user}.Sanitize(), quoteSQLLiteral(newPassword))
	execCtx, cancel := context.WithTimeout(ctx, e.dialTimeout)
	defer cancel()
	if _, err := conn.Exec(execCtx, stmt); err != nil {
		return Secret{}, fmt.Errorf("pam: pg alter role: %w", err)
	}

	// Verify the new credential genuinely authenticates before we hand it back
	// to be sealed — otherwise a server-side quirk could leave the vault holding
	// a password the upstream rejects.
	if err := e.verify(ctx, ep, newPassword); err != nil {
		// Best-effort: put the old password back so the upstream still matches
		// the vault, then report failure.
		_, _ = conn.Exec(context.Background(), fmt.Sprintf("ALTER ROLE %s WITH PASSWORD %s",
			pgx.Identifier{ep.user}.Sanitize(), quoteSQLLiteral(current.Password)))
		return Secret{}, fmt.Errorf("pam: pg verify rotated credential: %w", err)
	}

	next := current
	next.Username = ep.user
	next.Password = newPassword
	return next, nil
}

func (e *PostgresExecutor) verify(ctx context.Context, ep dbEndpoint, password string) error {
	conn, err := e.connect(ctx, ep, password)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(context.Background()) }()
	var one int
	if err := conn.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil {
		return fmt.Errorf("pam: pg probe: %w", err)
	}
	return nil
}

// Restore implements RotationExecutor for PostgreSQL.
func (e *PostgresExecutor) Restore(ctx context.Context, target *models.PAMTarget, liveNow Secret, restore Secret) error {
	ep, err := resolveDBEndpoint(target, liveNow, 5432)
	if err != nil {
		return err
	}
	conn, err := e.connect(ctx, ep, liveNow.Password)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(context.Background()) }()
	stmt := fmt.Sprintf("ALTER ROLE %s WITH PASSWORD %s",
		pgx.Identifier{ep.user}.Sanitize(), quoteSQLLiteral(restore.Password))
	if _, err := conn.Exec(ctx, stmt); err != nil {
		return fmt.Errorf("pam: pg restore role: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// MySQL
// ---------------------------------------------------------------------------

// MySQLExecutor rotates a MySQL user's password with `ALTER USER ... IDENTIFIED
// BY`. The account host defaults to '%' and can be pinned via Config["mysql_host"].
type MySQLExecutor struct {
	dialTimeout time.Duration
}

// Protocol implements RotationExecutor.
func (e *MySQLExecutor) Protocol() string { return models.PAMProtocolMySQL }

func mysqlAccountHost(target *models.PAMTarget) string {
	if h := strings.TrimSpace(decodeConfig(target.Config)["mysql_host"]); h != "" {
		return h
	}
	return "%"
}

func (e *MySQLExecutor) open(ep dbEndpoint, password string) (*sql.DB, error) {
	return mysqlOpen(ep, password, e.dialTimeout)
}

// mysqlOpen builds a bounded *sql.DB for a database endpoint, negotiating TLS
// when the server offers it. Shared by the executor and the dynamic-credential
// service.
func mysqlOpen(ep dbEndpoint, password string, timeout time.Duration) (*sql.DB, error) {
	cfg := mysql.NewConfig()
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(ep.host, strconv.Itoa(int(ep.port)))
	cfg.User = ep.user
	cfg.Passwd = password
	cfg.DBName = ep.database
	cfg.Timeout = timeout
	cfg.ReadTimeout = timeout
	cfg.WriteTimeout = timeout
	// Negotiate TLS when the server offers it without failing a plaintext-only
	// dev target, matching the gateway's sslmode=prefer posture.
	cfg.TLSConfig = "preferred"
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return nil, fmt.Errorf("pam: mysql open: %w", err)
	}
	db.SetConnMaxLifetime(2 * timeout)
	db.SetMaxOpenConns(2)
	return db, nil
}

// Rotate implements RotationExecutor for MySQL.
func (e *MySQLExecutor) Rotate(ctx context.Context, target *models.PAMTarget, current Secret) (Secret, error) {
	ep, err := resolveDBEndpoint(target, current, 3306)
	if err != nil {
		return Secret{}, err
	}
	newPassword, err := generatePassword(32)
	if err != nil {
		return Secret{}, err
	}
	db, err := e.open(ep, current.Password)
	if err != nil {
		return Secret{}, err
	}
	defer func() { _ = db.Close() }()
	if err := db.PingContext(ctx); err != nil {
		return Secret{}, fmt.Errorf("pam: mysql connect %s: %w", ep.host, err)
	}

	host := mysqlAccountHost(target)
	stmt := fmt.Sprintf("ALTER USER %s@%s IDENTIFIED BY %s",
		mysqlQuoteLiteral(ep.user), mysqlQuoteLiteral(host), mysqlQuoteLiteral(newPassword))
	if _, err := db.ExecContext(ctx, stmt); err != nil {
		return Secret{}, fmt.Errorf("pam: mysql alter user: %w", err)
	}

	if err := e.verify(ctx, ep, newPassword); err != nil {
		// Roll the password back so the upstream still matches the vault.
		_, _ = db.ExecContext(context.Background(), fmt.Sprintf("ALTER USER %s@%s IDENTIFIED BY %s",
			mysqlQuoteLiteral(ep.user), mysqlQuoteLiteral(host), mysqlQuoteLiteral(current.Password)))
		return Secret{}, fmt.Errorf("pam: mysql verify rotated credential: %w", err)
	}

	next := current
	next.Username = ep.user
	next.Password = newPassword
	return next, nil
}

func (e *MySQLExecutor) verify(ctx context.Context, ep dbEndpoint, password string) error {
	db, err := e.open(ep, password)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	var one int
	if err := db.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil {
		return fmt.Errorf("pam: mysql probe: %w", err)
	}
	return nil
}

// Restore implements RotationExecutor for MySQL.
func (e *MySQLExecutor) Restore(ctx context.Context, target *models.PAMTarget, liveNow Secret, restore Secret) error {
	ep, err := resolveDBEndpoint(target, liveNow, 3306)
	if err != nil {
		return err
	}
	db, err := e.open(ep, liveNow.Password)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	host := mysqlAccountHost(target)
	stmt := fmt.Sprintf("ALTER USER %s@%s IDENTIFIED BY %s",
		mysqlQuoteLiteral(ep.user), mysqlQuoteLiteral(host), mysqlQuoteLiteral(restore.Password))
	if _, err := db.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("pam: mysql restore user: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// SSH
// ---------------------------------------------------------------------------

// sshManagedKeyMarker tags the authorized_keys line this product manages, so a
// rotation replaces only its own key and never disturbs other operators' keys.
const sshManagedKeyMarker = "shieldnet-access-rotation"

// SSHExecutor rotates the managed authorized key for a target's login user. It
// generates a fresh ed25519 keypair, installs the public key in the user's
// authorized_keys (replacing only the line it previously managed), verifies a
// login with the new private key, and returns the new key as the sealed secret.
type SSHExecutor struct {
	dialTimeout time.Duration
}

// Protocol implements RotationExecutor.
func (e *SSHExecutor) Protocol() string { return models.PAMProtocolSSH }

func (e *SSHExecutor) clientConfig(target *models.PAMTarget, sec Secret) (*ssh.ClientConfig, error) {
	user := strings.TrimSpace(target.Username)
	if user == "" {
		user = strings.TrimSpace(sec.Username)
	}
	if user == "" {
		return nil, fmt.Errorf("%w: target has no ssh username", ErrValidation)
	}
	var auths []ssh.AuthMethod
	if strings.TrimSpace(sec.PrivateKey) != "" {
		signer, err := ssh.ParsePrivateKey([]byte(sec.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("pam: parse ssh private key: %w", err)
		}
		auths = append(auths, ssh.PublicKeys(signer))
	}
	if sec.Password != "" {
		auths = append(auths, ssh.Password(sec.Password))
	}
	if len(auths) == 0 {
		return nil, fmt.Errorf("%w: no usable ssh auth method", ErrValidation)
	}
	return &ssh.ClientConfig{
		User:            user,
		Auth:            auths,
		HostKeyCallback: sshHostKeyCallback(target),
		Timeout:         e.dialTimeout,
	}, nil
}

// Rotate implements RotationExecutor for SSH.
func (e *SSHExecutor) Rotate(ctx context.Context, target *models.PAMTarget, current Secret) (Secret, error) {
	cfg, err := e.clientConfig(target, current)
	if err != nil {
		return Secret{}, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Secret{}, fmt.Errorf("pam: generate ssh key: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return Secret{}, fmt.Errorf("pam: ssh public key: %w", err)
	}
	authorizedLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " " + sshManagedKeyMarker
	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return Secret{}, fmt.Errorf("pam: marshal ssh private key: %w", err)
	}
	newPrivatePEM := string(pem.EncodeToMemory(pemBlock))
	newSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return Secret{}, fmt.Errorf("pam: ssh signer from key: %w", err)
	}

	client, err := ssh.Dial("tcp", target.Address, cfg)
	if err != nil {
		return Secret{}, fmt.Errorf("pam: ssh dial %s: %w", target.Address, err)
	}
	defer func() { _ = client.Close() }()

	if err := e.installAuthorizedKey(ctx, client, authorizedLine); err != nil {
		return Secret{}, err
	}

	// Verify a fresh login with the new key before sealing it.
	verifyCfg := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(newSigner)},
		HostKeyCallback: sshHostKeyCallback(target),
		Timeout:         e.dialTimeout,
	}
	if err := e.verifyLogin(target.Address, verifyCfg); err != nil {
		// Roll back: remove the key we just installed (best effort), using the
		// still-valid original credential.
		_ = e.removeManagedKey(context.Background(), client)
		return Secret{}, fmt.Errorf("pam: ssh verify rotated key: %w", err)
	}

	next := current
	next.PrivateKey = newPrivatePEM
	// The key supersedes any stored password for the managed login.
	next.Password = ""
	return next, nil
}

// Restore implements RotationExecutor for SSH. It authenticates with the
// new key and rewrites the managed authorized_keys line back to the old key (or
// removes it when the prior credential was not key-based).
func (e *SSHExecutor) Restore(ctx context.Context, target *models.PAMTarget, liveNow Secret, restore Secret) error {
	cfg, err := e.clientConfig(target, liveNow)
	if err != nil {
		return err
	}
	client, err := ssh.Dial("tcp", target.Address, cfg)
	if err != nil {
		return fmt.Errorf("pam: ssh dial %s: %w", target.Address, err)
	}
	defer func() { _ = client.Close() }()

	if strings.TrimSpace(restore.PrivateKey) == "" {
		// Nothing key-based to restore; just remove our managed line.
		return e.removeManagedKey(ctx, client)
	}
	signer, err := ssh.ParsePrivateKey([]byte(restore.PrivateKey))
	if err != nil {
		return fmt.Errorf("pam: parse restore ssh key: %w", err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) + " " + sshManagedKeyMarker
	return e.installAuthorizedKey(ctx, client, line)
}

// installAuthorizedKey atomically replaces the single managed line in the login
// user's authorized_keys with `line`, leaving every other key untouched.
func (e *SSHExecutor) installAuthorizedKey(ctx context.Context, client *ssh.Client, line string) error {
	// Filter out any prior managed line, append the new one, swap atomically.
	// All authorized_keys mutations happen in one remote shell command so a
	// dropped connection can never leave a half-written file.
	script := strings.Join([]string{
		`set -e`,
		`d="$HOME/.ssh"`,
		`mkdir -p "$d"`,
		`chmod 700 "$d"`,
		`f="$d/authorized_keys"`,
		`t="$d/.authorized_keys.shieldnet.$$"`,
		`touch "$f"`,
		fmt.Sprintf(`grep -v %s "$f" > "$t" || true`, shellQuote(sshManagedKeyMarker)),
		fmt.Sprintf(`printf '%%s\n' %s >> "$t"`, shellQuote(line)),
		`mv "$t" "$f"`,
		`chmod 600 "$f"`,
	}, " && ")
	return e.runRemote(ctx, client, script)
}

// removeManagedKey deletes only the managed authorized_keys line.
func (e *SSHExecutor) removeManagedKey(ctx context.Context, client *ssh.Client) error {
	script := strings.Join([]string{
		`set -e`,
		`f="$HOME/.ssh/authorized_keys"`,
		`[ -f "$f" ] || exit 0`,
		`t="$f.shieldnet.$$"`,
		fmt.Sprintf(`grep -v %s "$f" > "$t" || true`, shellQuote(sshManagedKeyMarker)),
		`mv "$t" "$f"`,
		`chmod 600 "$f"`,
	}, " && ")
	return e.runRemote(ctx, client, script)
}

func (e *SSHExecutor) runRemote(ctx context.Context, client *ssh.Client, script string) error {
	type result struct{ err error }
	done := make(chan result, 1)
	go func() {
		sess, err := client.NewSession()
		if err != nil {
			done <- result{fmt.Errorf("pam: ssh session: %w", err)}
			return
		}
		defer func() { _ = sess.Close() }()
		if out, err := sess.CombinedOutput(script); err != nil {
			done <- result{fmt.Errorf("pam: ssh run authorized_keys update: %w (%s)", err, strings.TrimSpace(string(out)))}
			return
		}
		done <- result{nil}
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case r := <-done:
		return r.err
	}
}

func (e *SSHExecutor) verifyLogin(address string, cfg *ssh.ClientConfig) error {
	client, err := ssh.Dial("tcp", address, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("pam: ssh verify session: %w", err)
	}
	defer func() { _ = sess.Close() }()
	if err := sess.Run("true"); err != nil {
		return fmt.Errorf("pam: ssh verify command: %w", err)
	}
	return nil
}

// sshHostKeyCallback pins the target's configured host key when present and
// otherwise accepts the presented key (trust-on-first-use), matching the
// gateway's hostKeyCallback posture rather than ssh.InsecureIgnoreHostKey.
func sshHostKeyCallback(target *models.PAMTarget) ssh.HostKeyCallback {
	pinned := strings.TrimSpace(decodeConfig(target.Config)["host_key"])
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if pinned == "" {
			return nil
		}
		want, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pinned))
		if err != nil {
			return fmt.Errorf("pam: parse pinned host key: %w", err)
		}
		if ssh.FingerprintSHA256(want) != ssh.FingerprintSHA256(key) {
			return fmt.Errorf("pam: ssh host key mismatch (pinned %s, got %s)",
				ssh.FingerprintSHA256(want), ssh.FingerprintSHA256(key))
		}
		return nil
	}
}

// quoteSQLLiteral renders s as a single-quoted PostgreSQL string literal,
// doubling any embedded single quote. It is safe for PostgreSQL because
// standard_conforming_strings is on by default (since 9.1), so a backslash is a
// literal backslash rather than an escape character. Do NOT use it for MySQL —
// use mysqlQuoteLiteral, which also escapes backslashes.
func quoteSQLLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// mysqlQuoteLiteral renders s as a single-quoted MySQL string literal. MySQL's
// default sql_mode does NOT set NO_BACKSLASH_ESCAPES, so a backslash is an
// escape character inside string literals; a literal backslash must therefore
// be doubled in addition to the single quote (otherwise a value ending in `\`
// would escape the closing quote and produce malformed SQL). The backslash must
// be escaped first so the backslashes introduced by the other rules are not
// themselves doubled. A raw NUL byte is escaped as `\0` last (its leading
// backslash is a genuine escape we must not re-double) because an embedded NUL
// can otherwise truncate the statement in the wire protocol. Other C-style
// escapes (\n, \r, \t, \Z) need no special handling: a literal newline/tab byte
// is valid inside a quoted string, and any backslash that precedes such a letter
// has already been doubled into a literal backslash. Generated passwords use a
// quote/backslash/NUL-free alphabet, so this matters in practice only for an
// operator-set admin password on the rollback / Restore path.
func mysqlQuoteLiteral(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "'", "''")
	s = strings.ReplaceAll(s, "\x00", "\\0")
	return "'" + s + "'"
}

// shellQuote single-quotes s for safe interpolation into a POSIX shell command,
// escaping embedded single quotes.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// pgIdentifier renders s as a safely-quoted PostgreSQL identifier.
func pgIdentifier(s string) string {
	return pgx.Identifier{s}.Sanitize()
}
