package gateway

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

func TestApplyKerberosUpstreamAuth(t *testing.T) {
	cases := []struct {
		name        string
		cfg         map[string]string
		defaultSvc  string
		wantApplied bool
		wantSpn     string
		wantSrv     string
	}{
		{name: "no kerberos keys", cfg: map[string]string{"database": "app"}, defaultSvc: "postgres", wantApplied: false},
		{name: "auth_mode kerberos uses default service", cfg: map[string]string{"auth_mode": "kerberos"}, defaultSvc: "postgres", wantApplied: true, wantSrv: "postgres"},
		{name: "auth_mode gssapi case-insensitive", cfg: map[string]string{"auth_mode": "GSSAPI"}, defaultSvc: "pg", wantApplied: true, wantSrv: "pg"},
		{name: "explicit spn", cfg: map[string]string{"krb_spn": "postgres/db.example.com"}, defaultSvc: "postgres", wantApplied: true, wantSpn: "postgres/db.example.com", wantSrv: "postgres"},
		{name: "explicit service overrides default", cfg: map[string]string{"krb_service": "pgprod"}, defaultSvc: "postgres", wantApplied: true, wantSrv: "pgprod"},
		{name: "no default service leaves srv empty", cfg: map[string]string{"auth_mode": "kerberos"}, defaultSvc: "", wantApplied: true, wantSrv: ""},
		{name: "whitespace-only keys ignored", cfg: map[string]string{"krb_spn": "  ", "auth_mode": "  "}, defaultSvc: "postgres", wantApplied: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := pgconn.ParseConfig("")
			if err != nil {
				t.Fatalf("ParseConfig: %v", err)
			}
			cfg.Password = "vault-secret"
			applied := applyKerberosUpstreamAuth(cfg, tc.cfg, tc.defaultSvc)
			if applied != tc.wantApplied {
				t.Fatalf("applied = %v, want %v", applied, tc.wantApplied)
			}
			if !tc.wantApplied {
				if cfg.Password != "vault-secret" {
					t.Fatalf("non-kerberos dial must keep the vault password, got %q", cfg.Password)
				}
				return
			}
			if cfg.Password != "" {
				t.Fatalf("kerberos dial must clear the vault password, got %q", cfg.Password)
			}
			if cfg.KerberosSpn != tc.wantSpn {
				t.Fatalf("KerberosSpn = %q, want %q", cfg.KerberosSpn, tc.wantSpn)
			}
			if cfg.KerberosSrvName != tc.wantSrv {
				t.Fatalf("KerberosSrvName = %q, want %q", cfg.KerberosSrvName, tc.wantSrv)
			}
		})
	}
}

func TestRegisterPostgresGSSProviderValidation(t *testing.T) {
	// A minimal but well-formed krb5.conf so the failure under test is the
	// keytab, not the config parse.
	dir := t.TempDir()
	krb5Conf := filepath.Join(dir, "krb5.conf")
	if err := os.WriteFile(krb5Conf, []byte("[libdefaults]\n  default_realm = EXAMPLE.COM\n\n[realms]\n  EXAMPLE.COM = {\n    kdc = kdc.example.com\n  }\n"), 0o600); err != nil {
		t.Fatalf("write krb5.conf: %v", err)
	}

	cases := []struct {
		name     string
		settings KerberosSettings
	}{
		{name: "missing keytab path", settings: KerberosSettings{Krb5ConfPath: krb5Conf, Username: "gw", Realm: "EXAMPLE.COM"}},
		{name: "missing username", settings: KerberosSettings{Krb5ConfPath: krb5Conf, KeytabPath: filepath.Join(dir, "x.keytab"), Realm: "EXAMPLE.COM"}},
		{name: "missing realm", settings: KerberosSettings{Krb5ConfPath: krb5Conf, KeytabPath: filepath.Join(dir, "x.keytab"), Username: "gw"}},
		{name: "unreadable krb5.conf", settings: KerberosSettings{Krb5ConfPath: filepath.Join(dir, "nope.conf"), KeytabPath: filepath.Join(dir, "x.keytab"), Username: "gw", Realm: "EXAMPLE.COM"}},
		{name: "missing keytab file", settings: KerberosSettings{Krb5ConfPath: krb5Conf, KeytabPath: filepath.Join(dir, "absent.keytab"), Username: "gw", Realm: "EXAMPLE.COM"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// These cases all fail local validation BEFORE the process-global
			// RegisterGSSProvider is touched, so they do not mutate global state.
			if err := RegisterPostgresGSSProvider(tc.settings); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// fakeGSSProvider is a pgconn.GSS double that records which token method pgconn
// drove and completes the handshake on the first Continue, so the upstream GSS
// path can be exercised without a live KDC.
type fakeGSSProvider struct {
	mu          sync.Mutex
	spnUsed     string
	hostUsed    string
	serviceUsed string
	continued   bool
}

func (p *fakeGSSProvider) GetInitToken(host, service string) ([]byte, error) {
	p.mu.Lock()
	p.hostUsed, p.serviceUsed = host, service
	p.mu.Unlock()
	return []byte("fake-init-token"), nil
}

func (p *fakeGSSProvider) GetInitTokenFromSPN(spn string) ([]byte, error) {
	p.mu.Lock()
	p.spnUsed = spn
	p.mu.Unlock()
	return []byte("fake-init-token-spn"), nil
}

func (p *fakeGSSProvider) Continue(_ []byte) (bool, []byte, error) {
	p.mu.Lock()
	p.continued = true
	p.mu.Unlock()
	return true, nil, nil
}

// fakePgGSSDialer hands pgconn a fresh in-memory connection per dial attempt
// (sslmode=prefer probes TLS then falls back to plaintext, so DialTarget is
// called twice) and runs a fake PostgreSQL server on the far end that demands
// GSSAPI, sends one AuthenticationGSSContinue, then accepts.
type fakePgGSSDialer struct {
	t    *testing.T
	mu   sync.Mutex
	errs []error
}

func (d *fakePgGSSDialer) DialTarget(_ context.Context, _ *models.PAMTarget) (net.Conn, error) {
	client, server := pipeConn(d.t)
	go d.serve(server)
	return client, nil
}

func (d *fakePgGSSDialer) recordErr(err error) {
	d.mu.Lock()
	d.errs = append(d.errs, err)
	d.mu.Unlock()
}

func (d *fakePgGSSDialer) serve(server net.Conn) {
	defer func() { _ = server.Close() }()
	be := pgproto3.NewBackend(server, server)
	for {
		msg, err := be.ReceiveStartupMessage()
		if err != nil {
			// Closed by pgconn after the TLS probe was refused — expected.
			return
		}
		switch msg.(type) {
		case *pgproto3.SSLRequest, *pgproto3.GSSEncRequest:
			if _, err := server.Write([]byte("N")); err != nil {
				d.recordErr(err)
				return
			}
		case *pgproto3.StartupMessage:
			if err := d.serveGSS(be); err != nil {
				d.recordErr(err)
			}
			return
		default:
			d.recordErr(fmt.Errorf("fake pg: unexpected startup %T", msg))
			return
		}
	}
}

func (d *fakePgGSSDialer) serveGSS(be *pgproto3.Backend) error {
	be.Send(&pgproto3.AuthenticationGSS{})
	if err := be.Flush(); err != nil {
		return err
	}
	if err := be.SetAuthType(pgproto3.AuthTypeGSS); err != nil {
		return err
	}
	msg, err := be.Receive()
	if err != nil {
		return err
	}
	if _, ok := msg.(*pgproto3.GSSResponse); !ok {
		return fmt.Errorf("fake pg: expected GSSResponse, got %T", msg)
	}
	be.Send(&pgproto3.AuthenticationGSSContinue{Data: []byte("fake-server-token")})
	be.Send(&pgproto3.AuthenticationOk{})
	be.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "15.0 (fake)"})
	be.Send(&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"})
	be.Send(&pgproto3.BackendKeyData{ProcessID: 1, SecretKey: 2})
	be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	return be.Flush()
}

func TestPostgresProxyDialUpstreamKerberos(t *testing.T) {
	cases := []struct {
		name        string
		targetCfg   map[string]string
		wantSpn     string
		wantHost    string
		wantService string
	}{
		{
			name:      "explicit spn",
			targetCfg: map[string]string{"auth_mode": "kerberos", "krb_spn": "postgres/db.example.com"},
			wantSpn:   "postgres/db.example.com",
		},
		{
			name:        "host+service spn",
			targetCfg:   map[string]string{"auth_mode": "kerberos"},
			wantHost:    "127.0.0.1",
			wantService: "postgres",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prov := &fakeGSSProvider{}
			pgconn.RegisterGSSProvider(func() (pgconn.GSS, error) { return prov, nil })
			defer pgconn.RegisterGSSProvider(nil)

			dialer := &fakePgGSSDialer{t: t}
			p := &PostgresProxy{dialer: dialer, dialTimeout: 5 * time.Second, kerberosService: "postgres"}
			leased := &pam.LeasedSession{
				Target: &models.PAMTarget{
					Address:  "127.0.0.1:5432",
					Username: "pguser",
					Config:   jsonConfig(t, tc.targetCfg),
				},
				Secret: pam.Secret{Username: "pguser", Password: "vault-secret"},
			}

			hj, err := p.dialUpstream(context.Background(), leased, "")
			if err != nil {
				t.Fatalf("dialUpstream: %v", err)
			}
			if hj == nil || hj.Conn == nil {
				t.Fatal("dialUpstream returned nil hijacked conn")
			}
			_ = hj.Conn.Close()

			prov.mu.Lock()
			defer prov.mu.Unlock()
			if !prov.continued {
				t.Fatal("GSS handshake never reached Continue")
			}
			if tc.wantSpn != "" && prov.spnUsed != tc.wantSpn {
				t.Fatalf("spnUsed = %q, want %q", prov.spnUsed, tc.wantSpn)
			}
			if tc.wantHost != "" {
				if prov.hostUsed != tc.wantHost {
					t.Fatalf("hostUsed = %q, want %q", prov.hostUsed, tc.wantHost)
				}
				if prov.serviceUsed != tc.wantService {
					t.Fatalf("serviceUsed = %q, want %q", prov.serviceUsed, tc.wantService)
				}
			}

			dialer.mu.Lock()
			defer dialer.mu.Unlock()
			if len(dialer.errs) > 0 {
				t.Fatalf("fake pg backend errors: %v", dialer.errs)
			}
		})
	}
}
