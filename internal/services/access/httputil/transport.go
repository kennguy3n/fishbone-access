// transport.go centralises the OUTBOUND HTTP transport that every access
// connector shares through NewRetryClient. The control plane fans out to
// thousands of SME tenants, each of whose connectors talk to a different
// upstream SaaS API (Okta, Monday, Google, …), so the outbound call pattern is
// HIGH-CARDINALITY: many distinct hosts, bursty per-host, and dominated by
// idle-between-syncs time for the large dormant-trial fraction.
//
// Go's http.DefaultTransport is tuned for a browser-like workload (a handful of
// hosts) — MaxIdleConnsPerHost defaults to 2, which throttles a connector that
// pages an upstream directory and forces constant TCP+TLS re-handshakes under
// fan-out. A single process-wide tuned transport fixes this for every connector
// at once WITHOUT editing any connector file: connectors obtain their client
// via httputil.NewRetryClient, and that constructor installs SharedTransport().
//
// One pool shared across all connectors is deliberate: idle connections are
// reclaimed by IdleConnTimeout, so a dormant tenant whose connector stops
// syncing contributes zero steady-state sockets, while an active tenant reuses
// warm connections to its upstreams. The total idle-connection ceiling
// (MaxIdleConns) bounds the process file-descriptor footprint regardless of how
// many tenants are active at once.
package httputil

import (
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

// Transport tuning defaults. These are sized for many-tenant connector
// fan-out, not a browser. Each is overridable via the matching ACCESS_HTTP_*
// environment variable (see resolveTransportConfig) so an operator can retune
// per deployment tier without a rebuild; deploy/ documents the recommended
// values for the 5,000-tenant case.
const (
	// defaultMaxIdleConns caps total kept-warm connections across ALL upstream
	// hosts. It bounds the process FD/socket footprint: even with thousands of
	// tenants, the pool never holds more than this many idle sockets.
	defaultMaxIdleConns = 256
	// defaultMaxIdleConnsPerHost lifts Go's stingy per-host default of 2. A
	// connector that pages a single upstream directory (e.g. listing users)
	// benefits from a small warm pool to that host; 32 keeps a healthy reuse
	// window without letting one busy upstream starve the global ceiling.
	defaultMaxIdleConnsPerHost = 32
	// defaultMaxConnsPerHost bounds TOTAL (active + idle) connections to one
	// host so a single misbehaving upstream cannot consume unbounded sockets.
	// 0 would mean unlimited; we cap it to protect the process under fan-out.
	defaultMaxConnsPerHost = 64
	// defaultIdleConnTimeout reclaims idle connections quickly so a tenant that
	// goes quiet (the common dormant-trial case) stops holding sockets. Short
	// enough for near-zero steady-state cost, long enough to span the gap
	// between a connector's paginated calls.
	defaultIdleConnTimeout = 90 * time.Second
	// defaultTLSHandshakeTimeout / defaultExpectContinueTimeout mirror the
	// stdlib defaults; named here so the whole transport is configured in one
	// place rather than inheriting opaque defaults.
	defaultTLSHandshakeTimeout   = 10 * time.Second
	defaultExpectContinueTimeout = 1 * time.Second
	// defaultDialTimeout / defaultDialKeepAlive bound connection establishment
	// so a black-holed upstream fails fast (the per-attempt request timeout in
	// NewRetryClient is the wider backstop).
	defaultDialTimeout   = 10 * time.Second
	defaultDialKeepAlive = 30 * time.Second
)

// TransportConfig is the resolved tuning applied to the shared transport. It is
// exported so tests (and an explicit boot-time override via
// ConfigureSharedTransport) can construct a transport deterministically.
type TransportConfig struct {
	MaxIdleConns          int
	MaxIdleConnsPerHost   int
	MaxConnsPerHost       int
	IdleConnTimeout       time.Duration
	TLSHandshakeTimeout   time.Duration
	ExpectContinueTimeout time.Duration
	DialTimeout           time.Duration
	DialKeepAlive         time.Duration
	// ForceAttemptHTTP2 keeps HTTP/2 negotiation on so a connector talking to an
	// HTTP/2-capable upstream multiplexes streams over one connection instead of
	// opening many — a large win under fan-out. Defaults to true.
	ForceAttemptHTTP2 bool
}

// DefaultTransportConfig returns the built-in tuning before any environment
// overrides are applied.
func DefaultTransportConfig() TransportConfig {
	return TransportConfig{
		MaxIdleConns:          defaultMaxIdleConns,
		MaxIdleConnsPerHost:   defaultMaxIdleConnsPerHost,
		MaxConnsPerHost:       defaultMaxConnsPerHost,
		IdleConnTimeout:       defaultIdleConnTimeout,
		TLSHandshakeTimeout:   defaultTLSHandshakeTimeout,
		ExpectContinueTimeout: defaultExpectContinueTimeout,
		DialTimeout:           defaultDialTimeout,
		DialKeepAlive:         defaultDialKeepAlive,
		ForceAttemptHTTP2:     true,
	}
}

// NewTransport builds a fresh *http.Transport from cfg. Callers that want the
// process-wide pool should use SharedTransport instead; this is for tests and
// for connectors that genuinely need an isolated transport (e.g. pinned mTLS).
func NewTransport(cfg TransportConfig) *http.Transport {
	dialer := &net.Dialer{
		Timeout:   cfg.DialTimeout,
		KeepAlive: cfg.DialKeepAlive,
	}
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     cfg.ForceAttemptHTTP2,
		MaxIdleConns:          cfg.MaxIdleConns,
		MaxIdleConnsPerHost:   cfg.MaxIdleConnsPerHost,
		MaxConnsPerHost:       cfg.MaxConnsPerHost,
		IdleConnTimeout:       cfg.IdleConnTimeout,
		TLSHandshakeTimeout:   cfg.TLSHandshakeTimeout,
		ExpectContinueTimeout: cfg.ExpectContinueTimeout,
	}
}

var (
	sharedTransportOnce sync.Once
	sharedTransport     *http.Transport
	// sharedTransportOverride is an optional config installed via
	// ConfigureSharedTransport before first use. nil ⇒ resolve from env.
	sharedTransportMu       sync.Mutex
	sharedTransportOverride *TransportConfig
)

// SharedTransport returns the process-wide tuned transport, building it on
// first use. Every connector that constructs its client via NewRetryClient
// shares this single connection pool, so retuning here (or via ACCESS_HTTP_*)
// changes outbound behaviour for the whole connector fleet at once.
//
// It is safe for concurrent use and initialises exactly once; the first caller
// wins. Because connectors construct their shared clients at package-init time
// (before main runs), the transport self-configures from the environment so no
// boot-time call is required for the tuning to take effect.
func SharedTransport() *http.Transport {
	sharedTransportOnce.Do(func() {
		sharedTransportMu.Lock()
		override := sharedTransportOverride
		sharedTransportMu.Unlock()
		cfg := resolveTransportConfig(override)
		sharedTransport = NewTransport(cfg)
	})
	return sharedTransport
}

// ConfigureSharedTransport installs an explicit TransportConfig to be used the
// first time SharedTransport is built. It returns false if the shared transport
// has already been built (the override came too late to take effect), so a
// caller can detect a wiring-order mistake rather than silently no-op. It is
// intended for tests and for a deployment that resolves tuning from a source
// other than the environment; the common path needs no call at all.
//
// Note the asymmetry with SharedTransport: when ConfigureSharedTransport wins
// the once it builds the transport from cfg VERBATIM, deliberately bypassing
// the ACCESS_HTTP_* env layering that resolveTransportConfig applies on the
// SharedTransport path. That is intentional — a caller passing an explicit
// config wants exactly that config, with no env bleed (which would make tests
// non-deterministic). A caller that does want env overrides on top should not
// use this function and instead let SharedTransport resolve them.
func ConfigureSharedTransport(cfg TransportConfig) (applied bool) {
	sharedTransportMu.Lock()
	sharedTransportOverride = &cfg
	sharedTransportMu.Unlock()
	built := false
	sharedTransportOnce.Do(func() {
		sharedTransport = NewTransport(cfg)
		built = true
	})
	return built
}

// resolveTransportConfig layers environment overrides over either an explicit
// override config or the built-in defaults.
func resolveTransportConfig(override *TransportConfig) TransportConfig {
	cfg := DefaultTransportConfig()
	if override != nil {
		cfg = *override
	}
	cfg.MaxIdleConns = envInt("ACCESS_HTTP_MAX_IDLE_CONNS", cfg.MaxIdleConns)
	cfg.MaxIdleConnsPerHost = envInt("ACCESS_HTTP_MAX_IDLE_CONNS_PER_HOST", cfg.MaxIdleConnsPerHost)
	cfg.MaxConnsPerHost = envInt("ACCESS_HTTP_MAX_CONNS_PER_HOST", cfg.MaxConnsPerHost)
	cfg.IdleConnTimeout = envDuration("ACCESS_HTTP_IDLE_CONN_TIMEOUT", cfg.IdleConnTimeout)
	cfg.TLSHandshakeTimeout = envDuration("ACCESS_HTTP_TLS_HANDSHAKE_TIMEOUT", cfg.TLSHandshakeTimeout)
	cfg.DialTimeout = envDuration("ACCESS_HTTP_DIAL_TIMEOUT", cfg.DialTimeout)
	cfg.ForceAttemptHTTP2 = envBool("ACCESS_HTTP_FORCE_HTTP2", cfg.ForceAttemptHTTP2)
	return cfg
}

// envInt reads a non-negative integer env var, falling back to def when unset,
// empty, unparseable, or negative (a negative pool bound is meaningless).
func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		return n
	}
	return def
}

// envDuration accepts a Go duration ("90s") or a bare integer (seconds).
func envDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return d
	}
	if n, err := strconv.Atoi(v); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return def
}

// envBool accepts the strconv.ParseBool set ("1","t","true","0","f","false"…).
func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	if b, err := strconv.ParseBool(v); err == nil {
		return b
	}
	return def
}
