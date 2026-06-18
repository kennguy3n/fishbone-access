package gateway

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5/pgconn"
	krbclient "github.com/jcmturner/gokrb5/v8/client"
	krbconfig "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// KerberosSettings is the validated material the Postgres proxy needs to
// authenticate to upstream clusters whose pg_hba demands `gss`. The gateway
// authenticates with ONE Kerberos service identity (its keytab principal);
// upstream pg_ident maps that principal to the target DB role. This is upstream
// *authentication* and is orthogonal to the operator hop, which stays on the
// connect token + TLS (the proxy still declines operator-side GSS encryption).
type KerberosSettings struct {
	// Krb5ConfPath is the krb5.conf describing the realm/KDC topology.
	Krb5ConfPath string
	// KeytabPath is the gateway's keytab holding the service principal's keys.
	KeytabPath string
	// Username is the principal primary (no realm), e.g. "shieldnet-gw".
	Username string
	// Realm is the principal realm, e.g. "EXAMPLE.COM".
	Realm string
}

// RegisterPostgresGSSProvider validates the local Kerberos material (krb5.conf
// parses, keytab is readable) and registers a pgconn GSS provider backed by
// gokrb5. The KDC login itself is deferred to the first upstream GSS handshake;
// only a SUCCESSFUL login is memoized and shared across connections, so a KDC
// outage degrades only Kerberos dials (and recovers on its own once the KDC is
// back) rather than failing gateway boot or wedging permanently.
//
// pgconn's provider registry is process-global (a single NewGSSFunc), which
// matches the gateway's single-service-identity model. Call it once at boot.
func RegisterPostgresGSSProvider(s KerberosSettings) error {
	if s.KeytabPath == "" || s.Username == "" || s.Realm == "" {
		return errors.New("gateway: kerberos requires keytab, username and realm")
	}
	krbConf, err := krbconfig.Load(s.Krb5ConfPath)
	if err != nil {
		return fmt.Errorf("gateway: load krb5.conf %q: %w", s.Krb5ConfPath, err)
	}
	kt, err := keytab.Load(s.KeytabPath)
	if err != nil {
		return fmt.Errorf("gateway: load keytab %q: %w", s.KeytabPath, err)
	}
	prov := &pgKerberosProvider{conf: krbConf, keytab: kt, username: s.Username, realm: s.Realm}
	pgconn.RegisterGSSProvider(prov.newGSS)
	return nil
}

// pgKerberosProvider holds the validated Kerberos material and lazily logs in,
// sharing the authenticated client across every upstream connection.
type pgKerberosProvider struct {
	conf     *krbconfig.Config
	keytab   *keytab.Keytab
	username string
	realm    string

	mu     sync.Mutex
	client *krbclient.Client
}

// login performs the keytab login lazily and memoizes only SUCCESS. A transient
// KDC failure (network blip, brief KDC restart) is returned to the caller but
// NOT cached, so the next upstream GSS dial retries the login — once the KDC
// recovers, Kerberos targets work again without a gateway restart. (sync.Once
// would have cached the first error forever, turning a momentary outage into
// permanent degradation, contradicting the "a KDC outage degrades only Kerberos
// targets" goal.) The mutex serializes concurrent first-dials so the login runs
// once, not once-per-racing-connection; the gokrb5 client renews its own TGT
// thereafter, so the single shared client then serves all connections.
func (p *pgKerberosProvider) login() (*krbclient.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.client != nil {
		return p.client, nil
	}
	cl := krbclient.NewWithKeytab(p.username, p.realm, p.keytab, p.conf, krbclient.DisablePAFXFAST(true))
	if err := cl.Login(); err != nil {
		return nil, fmt.Errorf("gateway: kerberos login as %s@%s: %w", p.username, p.realm, err)
	}
	p.client = cl
	return p.client, nil
}

// newGSS is the pgconn.NewGSSFunc. pgconn calls it once per upstream connection
// that negotiates GSSAPI.
func (p *pgKerberosProvider) newGSS() (pgconn.GSS, error) {
	cl, err := p.login()
	if err != nil {
		return nil, err
	}
	return &pgKerberosContext{client: cl}, nil
}

// pgKerberosContext is one GSSAPI/SPNEGO security context for a single upstream
// connection. It implements pgconn.GSS.
type pgKerberosContext struct {
	client *krbclient.Client
	spnego *spnego.SPNEGO
}

// GetInitToken builds the initial SPNEGO token for the SPN service/host (e.g.
// postgres/db.example.com), which is how pgconn maps the upstream host to a
// principal when no explicit SPN is configured.
func (c *pgKerberosContext) GetInitToken(host, service string) ([]byte, error) {
	return c.GetInitTokenFromSPN(service + "/" + host)
}

// GetInitTokenFromSPN builds the initial SPNEGO token for an explicit SPN.
func (c *pgKerberosContext) GetInitTokenFromSPN(spn string) ([]byte, error) {
	c.spnego = spnego.SPNEGOClient(c.client, spn)
	if err := c.spnego.AcquireCred(); err != nil {
		return nil, fmt.Errorf("gateway: kerberos acquire cred for %q: %w", spn, err)
	}
	token, err := c.spnego.InitSecContext()
	if err != nil {
		return nil, fmt.Errorf("gateway: kerberos init sec context for %q: %w", spn, err)
	}
	b, err := token.Marshal()
	if err != nil {
		return nil, fmt.Errorf("gateway: kerberos marshal init token: %w", err)
	}
	return b, nil
}

// Continue feeds the upstream's negotiation response back into SPNEGO and
// reports whether the handshake is complete. A non-empty out token is returned
// to pgconn when the server expects another round.
func (c *pgKerberosContext) Continue(inToken []byte) (bool, []byte, error) {
	if c.spnego == nil {
		return false, nil, errors.New("gateway: kerberos continue called before init")
	}
	var resp spnego.SPNEGOToken
	if err := resp.Unmarshal(inToken); err != nil {
		return false, nil, fmt.Errorf("gateway: kerberos unmarshal continue token: %w", err)
	}
	if !resp.Resp {
		return false, nil, errors.New("gateway: kerberos continue token is not a negotiation response")
	}
	switch resp.NegTokenResp.State() {
	case spnego.NegStateAcceptCompleted:
		return true, nil, nil
	case spnego.NegStateReject:
		return false, nil, errors.New("gateway: kerberos negotiation rejected by server")
	case spnego.NegStateAcceptIncomplete, spnego.NegStateRequestMIC:
		// Server wants another round (or a MIC); hand its response token back.
		return false, resp.NegTokenResp.ResponseToken, nil
	}
	return false, nil, fmt.Errorf("gateway: kerberos unexpected negotiation state %d", resp.NegTokenResp.State())
}

// applyKerberosUpstreamAuth configures GSSAPI/Kerberos authentication on cfg
// when the target EXPLICITLY opts into it via auth_mode=kerberos|gssapi. It
// returns true when Kerberos was applied. The krb_spn / krb_service keys only
// *parameterize* an already-opted-in target (explicit SPN / per-target service
// override); on a target without auth_mode they are ignored, NOT treated as an
// implicit opt-in. Requiring the explicit flag avoids a footgun: a stray
// krb_spn/krb_service key (copy-paste, schema confusion) on an otherwise
// password-authenticated target would otherwise silently drop its vault
// password (below) and surface a confusing GSSAPI error instead of just working.
//
// A Kerberos target carries no upstream password: the gateway proves identity
// with its service ticket via the registered GSS provider, so cfg.Password is
// cleared. The ticket exchange itself happens inside pgconn when the upstream
// answers the startup packet with AuthenticationGSS. When no provider is
// registered (Kerberos disabled) such a dial fails loudly with pgconn's
// "no GSSAPI provider registered" error rather than silently sending a stale
// secret — the correct outcome for a target marked Kerberos on a gateway that
// has Kerberos turned off.
func applyKerberosUpstreamAuth(cfg *pgconn.Config, targetCfg map[string]string, defaultService string) bool {
	mode := strings.ToLower(strings.TrimSpace(targetCfg["auth_mode"]))
	if mode != "kerberos" && mode != "gssapi" {
		return false
	}
	spn := strings.TrimSpace(targetCfg["krb_spn"])
	service := strings.TrimSpace(targetCfg["krb_service"])
	if spn != "" {
		cfg.KerberosSpn = spn
	}
	switch {
	case service != "":
		cfg.KerberosSrvName = service
	case defaultService != "":
		cfg.KerberosSrvName = defaultService
	}
	cfg.Password = ""
	return true
}
