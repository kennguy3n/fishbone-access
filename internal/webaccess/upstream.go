package webaccess

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/ssh"
	"gorm.io/datatypes"

	"github.com/kennguy3n/fishbone-access/internal/gateway"
	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// decodeTargetConfig parses a PAM target's free-form JSON config into a flat
// string map, mirroring the gateway's unexported helper of the same purpose so
// the browser bridge reads pinned host keys / database names the same way the
// native proxies do. A malformed or empty config yields an empty map (the
// caller treats every key as absent), never an error, so a single bad config
// row cannot break the connect path.
func decodeTargetConfig(raw datatypes.JSON) map[string]string {
	out := map[string]string{}
	if len(raw) == 0 {
		return out
	}
	// Decode permissively: values may be strings or other JSON scalars, so
	// unmarshal into any and stringify, rather than failing the whole map on a
	// single non-string value.
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return out
	}
	for k, v := range generic {
		switch t := v.(type) {
		case string:
			out[k] = t
		case float64:
			out[k] = strconv.FormatFloat(t, 'f', -1, 64)
		case bool:
			out[k] = strconv.FormatBool(t)
		}
	}
	return out
}

// upstreamSSHUser resolves the upstream account the same way every gateway
// proxy does: the target's configured username, falling back to the secret's.
func upstreamSSHUser(leased *pam.LeasedSession) string {
	if leased.Target.Username != "" {
		return leased.Target.Username
	}
	return leased.Secret.Username
}

// dialUpstreamSSH opens an SSH client connection to the target, preferring a
// freshly minted CA certificate (when a CA is configured and the target trusts
// it) and falling back to the JIT-injected vault credential — private key then
// password — exactly like the native SSH proxy. The upstream username is the
// target's configured account, never client-supplied, and the host key is
// verified against the target's pinned key when one is configured.
func dialUpstreamSSH(leased *pam.LeasedSession, ca *gateway.SSHCertificateAuthority, dialTimeout time.Duration) (*ssh.Client, error) {
	target := leased.Target
	user := upstreamSSHUser(leased)
	if user == "" {
		return nil, errors.New("webaccess: target has no upstream username")
	}

	var auths []ssh.AuthMethod
	if ca != nil {
		if certSigner, err := ca.MintEphemeralCert(user); err == nil {
			auths = append(auths, ssh.PublicKeys(certSigner))
		}
	}
	if leased.Secret.PrivateKey != "" {
		if signer, err := ssh.ParsePrivateKey([]byte(leased.Secret.PrivateKey)); err == nil {
			auths = append(auths, ssh.PublicKeys(signer))
		}
	}
	if leased.Secret.Password != "" {
		auths = append(auths, ssh.Password(leased.Secret.Password))
	}
	if len(auths) == 0 {
		return nil, errors.New("webaccess: no usable upstream auth method")
	}

	clientCfg := &ssh.ClientConfig{
		User:            user,
		Auth:            auths,
		HostKeyCallback: hostKeyCallback(target),
		Timeout:         dialTimeout,
	}
	client, err := ssh.Dial("tcp", target.Address, clientCfg)
	if err != nil {
		return nil, fmt.Errorf("webaccess: ssh dial %s: %w", target.Address, err)
	}
	return client, nil
}

// hostKeyCallback verifies the upstream host key against a key pinned in the
// target config ("host_key": an authorized-keys line) when present, mirroring
// the gateway's verification. Pinning is the secure path; with no pin the
// callback accepts the presented key (trust-on-first-use) rather than failing a
// target that has not yet pinned one. It never uses InsecureIgnoreHostKey, so a
// configured pin can never be silently bypassed.
func hostKeyCallback(target *models.PAMTarget) ssh.HostKeyCallback {
	pinned := ""
	if target != nil {
		pinned = strings.TrimSpace(decodeTargetConfig(target.Config)["host_key"])
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if pinned == "" {
			return nil
		}
		want, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pinned))
		if err != nil {
			return fmt.Errorf("webaccess: parse pinned host key: %w", err)
		}
		if ssh.FingerprintSHA256(want) != ssh.FingerprintSHA256(key) {
			return fmt.Errorf("webaccess: host key mismatch for %s (pinned %s, got %s)",
				hostname, ssh.FingerprintSHA256(want), ssh.FingerprintSHA256(key))
		}
		return nil
	}
}

// upstreamDBName resolves the database/schema to open for a DB-console session:
// the target config's "database", then the upstream username, mirroring the
// gateway's startupDatabase fallback so the browser console and the native
// proxy connect to the same default database.
func upstreamDBName(leased *pam.LeasedSession) string {
	cfg := decodeTargetConfig(leased.Target.Config)
	if db := strings.TrimSpace(cfg["database"]); db != "" {
		return db
	}
	user := leased.Target.Username
	if user == "" {
		user = leased.Secret.Username
	}
	return user
}

// dialUpstreamPostgres opens a pgx connection to the target with the JIT
// credential. TLS is preferred (sslmode=prefer semantics) so the gateway→target
// hop is encrypted when the server supports it, without failing a plaintext-only
// dev database.
func dialUpstreamPostgres(ctx context.Context, leased *pam.LeasedSession, dialTimeout time.Duration) (*pgx.Conn, error) {
	host, port, err := net.SplitHostPort(leased.Target.Address)
	if err != nil {
		return nil, fmt.Errorf("webaccess: parse target address: %w", err)
	}
	user := leased.Target.Username
	if user == "" {
		user = leased.Secret.Username
	}
	// sslmode=prefer is what gives pgx the opportunistic-TLS wiring we want: it
	// builds a TLS-first primary connection AND a plaintext fallback (in
	// cfg.Fallbacks), so an SSL-capable server is encrypted while a
	// plaintext-only server (a legacy or dev database) still connects. Setting
	// cfg.TLSConfig by hand on an empty-DSN config does NOT create that fallback,
	// so it fails closed against any server that refuses TLS. The host and port
	// live in the DSN so the generated fallback inherits them; credentials and
	// database are set on the shared config below. Certificate verification is
	// intentionally skipped (prefer semantics) — the gateway→DB hop runs inside
	// the operator's own network and mirrors the native pg proxy; the sensitive
	// operator↔gateway hop is the WebSocket's TLS.
	cfg, err := pgx.ParseConfig(fmt.Sprintf("host=%s port=%s sslmode=prefer", host, port))
	if err != nil {
		return nil, fmt.Errorf("webaccess: base pg config: %w", err)
	}
	cfg.User = user
	cfg.Password = leased.Secret.Password
	cfg.Database = upstreamDBName(leased)
	cfg.ConnectTimeout = dialTimeout

	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	conn, err := pgx.ConnectConfig(dialCtx, cfg)
	if err != nil {
		return nil, fmt.Errorf("webaccess: connect upstream postgres: %w", err)
	}
	return conn, nil
}

// dialUpstreamMySQL opens a database/sql connection to the MySQL target with the
// JIT credential. The pool is capped to a single connection so the console is a
// single, ordered session (statements run in the order the operator submits
// them) and holds exactly one upstream connection for its lifetime.
func dialUpstreamMySQL(ctx context.Context, leased *pam.LeasedSession, dialTimeout time.Duration) (*sql.DB, error) {
	user := leased.Target.Username
	if user == "" {
		user = leased.Secret.Username
	}
	c := mysql.NewConfig()
	c.User = user
	c.Passwd = leased.Secret.Password
	c.Net = "tcp"
	c.Addr = leased.Target.Address
	c.DBName = upstreamDBName(leased)
	c.Timeout = dialTimeout
	c.AllowNativePasswords = true
	// Interpolate parameters client-side is left off (default) so the driver
	// uses real prepared statements; the console runs ad-hoc text statements,
	// so there are no bound parameters to worry about either way.

	db, err := sql.Open("mysql", c.FormatDSN())
	if err != nil {
		return nil, fmt.Errorf("webaccess: open mysql: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	pingCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("webaccess: connect upstream mysql: %w", err)
	}
	return db, nil
}
