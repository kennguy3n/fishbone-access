package config

import (
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("ACCESS_ENV", "")
	t.Setenv("ACCESS_HTTP_ADDR", "")
	t.Setenv("ACCESS_DATABASE_URL", "")
	t.Setenv("IAM_CORE_ISSUER", "")

	cfg := Load()
	if cfg.Env != "dev" {
		t.Errorf("Env = %q, want dev", cfg.Env)
	}
	if cfg.HTTPAddr != ":8080" {
		t.Errorf("HTTPAddr = %q, want :8080", cfg.HTTPAddr)
	}
	if cfg.DatabaseConfigured() {
		t.Error("DatabaseConfigured() = true, want false when DSN unset")
	}
	if cfg.IAMCore.Configured() {
		t.Error("IAMCore.Configured() = true, want false when issuer unset")
	}
	if cfg.ShutdownTimeout != 10*time.Second {
		t.Errorf("ShutdownTimeout = %s, want 10s", cfg.ShutdownTimeout)
	}
}

func TestIAMCoreDerivedURLs(t *testing.T) {
	c := IAMCoreConfig{Issuer: "https://iam.example.com/"}
	if got, want := c.ResolvedJWKSURL(), "https://iam.example.com/oauth2/jwks"; got != want {
		t.Errorf("ResolvedJWKSURL() = %q, want %q", got, want)
	}
	if got, want := c.ResolvedDiscoveryURL(), "https://iam.example.com/.well-known/openid-configuration"; got != want {
		t.Errorf("ResolvedDiscoveryURL() = %q, want %q", got, want)
	}
	if got, want := c.ResolvedManagementBaseURL(), "https://iam.example.com"; got != want {
		t.Errorf("ResolvedManagementBaseURL() = %q, want %q", got, want)
	}
	if !c.Configured() {
		t.Error("Configured() = false, want true when issuer set")
	}
	// Issuer alone is enough for JWT validation but NOT for the management API.
	if c.ManagementConfigured() {
		t.Error("ManagementConfigured() = true without client credentials, want false")
	}
}

func TestManagementConfiguredRequiresClientCredentials(t *testing.T) {
	base := IAMCoreConfig{Issuer: "https://iam.example.com"}
	if base.ManagementConfigured() {
		t.Error("want false with no client credentials")
	}
	if (IAMCoreConfig{Issuer: "https://iam.example.com", ClientID: "id"}).ManagementConfigured() {
		t.Error("want false with client id but no secret")
	}
	full := IAMCoreConfig{Issuer: "https://iam.example.com", ClientID: "id", ClientSecret: "secret"}
	if !full.ManagementConfigured() {
		t.Error("want true with issuer + client id + secret")
	}
}

func TestIAMCoreExplicitURLsWin(t *testing.T) {
	c := IAMCoreConfig{
		Issuer:            "https://iam.example.com",
		JWKSURL:           "https://cdn.example.com/jwks",
		ManagementBaseURL: "https://mgmt.example.com/",
	}
	if got := c.ResolvedJWKSURL(); got != "https://cdn.example.com/jwks" {
		t.Errorf("explicit JWKSURL not honored: %q", got)
	}
	if got := c.ResolvedManagementBaseURL(); got != "https://mgmt.example.com" {
		t.Errorf("explicit ManagementBaseURL not honored: %q", got)
	}
}

func TestGetDurationParsing(t *testing.T) {
	t.Setenv("ACCESS_SHUTDOWN_TIMEOUT", "30")
	if got := Load().ShutdownTimeout; got != 30*time.Second {
		t.Errorf("bare-int duration = %s, want 30s", got)
	}
	t.Setenv("ACCESS_SHUTDOWN_TIMEOUT", "2m")
	if got := Load().ShutdownTimeout; got != 2*time.Minute {
		t.Errorf("duration string = %s, want 2m", got)
	}
}
