package httputil

import (
	"net/http"
	"testing"
	"time"
)

func TestDefaultTransportConfigTunedForFanout(t *testing.T) {
	cfg := DefaultTransportConfig()
	// The whole point of the package is to lift Go's browser-tuned defaults.
	if cfg.MaxIdleConnsPerHost <= http.DefaultMaxIdleConnsPerHost {
		t.Errorf("MaxIdleConnsPerHost = %d, want > stdlib default %d",
			cfg.MaxIdleConnsPerHost, http.DefaultMaxIdleConnsPerHost)
	}
	if cfg.MaxIdleConns <= 0 {
		t.Error("MaxIdleConns must be bounded (>0) to cap the FD footprint")
	}
	if cfg.MaxConnsPerHost <= 0 {
		t.Error("MaxConnsPerHost must be bounded (>0) so one upstream cannot starve sockets")
	}
	if !cfg.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 should default true for multiplexed fan-out")
	}
	if cfg.IdleConnTimeout <= 0 {
		t.Error("IdleConnTimeout must be set so dormant tenants release sockets")
	}
}

func TestNewTransportAppliesConfig(t *testing.T) {
	cfg := TransportConfig{
		MaxIdleConns:          128,
		MaxIdleConnsPerHost:   16,
		MaxConnsPerHost:       40,
		IdleConnTimeout:       45 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 2 * time.Second,
		DialTimeout:           7 * time.Second,
		DialKeepAlive:         15 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	tr := NewTransport(cfg)
	if tr.MaxIdleConns != 128 || tr.MaxIdleConnsPerHost != 16 || tr.MaxConnsPerHost != 40 {
		t.Errorf("conn bounds not applied: %+v", tr)
	}
	if tr.IdleConnTimeout != 45*time.Second {
		t.Errorf("IdleConnTimeout = %s, want 45s", tr.IdleConnTimeout)
	}
	if !tr.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 not applied")
	}
	if tr.DialContext == nil {
		t.Error("DialContext must be set so dial timeouts apply")
	}
	if tr.Proxy == nil {
		t.Error("Proxy must honour the environment (corporate egress proxies)")
	}
}

func TestSharedTransportIsSingletonAndUsedByRetryClient(t *testing.T) {
	a := SharedTransport()
	b := SharedTransport()
	if a != b {
		t.Fatal("SharedTransport must return the same instance across calls")
	}
	rc := NewRetryClient(0)
	if rc.HTTP.Transport != a {
		t.Fatal("NewRetryClient must install the shared transport so the whole connector fleet shares one pool")
	}
}

func TestEnvHelpers(t *testing.T) {
	t.Setenv("X_INT", "42")
	if got := envInt("X_INT", 7); got != 42 {
		t.Errorf("envInt = %d, want 42", got)
	}
	t.Setenv("X_INT", "-1") // negative rejected → default
	if got := envInt("X_INT", 7); got != 7 {
		t.Errorf("envInt(neg) = %d, want default 7", got)
	}
	t.Setenv("X_DUR", "2m")
	if got := envDuration("X_DUR", time.Second); got != 2*time.Minute {
		t.Errorf("envDuration = %s, want 2m", got)
	}
	t.Setenv("X_DUR", "30") // bare integer → seconds
	if got := envDuration("X_DUR", time.Second); got != 30*time.Second {
		t.Errorf("envDuration(bare) = %s, want 30s", got)
	}
	t.Setenv("X_BOOL", "false")
	if envBool("X_BOOL", true) {
		t.Error("envBool should parse false")
	}
}
