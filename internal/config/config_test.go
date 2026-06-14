package config

import (
	"strings"
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
	if cfg.DatabaseDriver != DriverPgx {
		t.Errorf("DatabaseDriver = %q, want %q (default)", cfg.DatabaseDriver, DriverPgx)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("default config failed Validate: %v", err)
	}
}

func TestDatabaseDriverParsing(t *testing.T) {
	tests := []struct {
		in   string
		want DatabaseDriver
	}{
		{"", DriverPgx},          // unset → default
		{"pgx", DriverPgx},       //
		{"gorm", DriverGorm},     //
		{"  GORM  ", DriverGorm}, // trimmed + lower-cased
		{"PgX", DriverPgx},       //
		{"sqlite", "sqlite"},     // unknown returned as-typed for Validate to reject
	}
	for _, tc := range tests {
		t.Setenv("ACCESS_DATABASE_DRIVER", tc.in)
		if got := Load().DatabaseDriver; got != tc.want {
			t.Errorf("ACCESS_DATABASE_DRIVER=%q → %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestValidateRejectsUnknownDriver(t *testing.T) {
	if err := (Config{DatabaseDriver: DriverGorm}).Validate(); err != nil {
		t.Errorf("gorm should validate: %v", err)
	}
	if err := (Config{DatabaseDriver: "mariadb"}).Validate(); err == nil {
		t.Error("unknown driver should fail Validate")
	}
}

func TestValidateKMSKeyVersion(t *testing.T) {
	const master = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // base64 of 32 zero bytes
	// Bad version is only an error when the master key is actually set; without
	// it the version is meaningless and must not block boot.
	if err := (Config{DatabaseDriver: DriverGorm, KMSKeyVersion: 0}).Validate(); err != nil {
		t.Errorf("version 0 without master key should validate: %v", err)
	}
	if err := (Config{DatabaseDriver: DriverGorm, KMSMasterKey: master, KMSKeyVersion: 0}).Validate(); err == nil {
		t.Error("version 0 with master key should fail Validate")
	}
	if err := (Config{DatabaseDriver: DriverGorm, KMSMasterKey: master, KMSKeyVersion: -1}).Validate(); err == nil {
		t.Error("negative version with master key should fail Validate")
	}
	if err := (Config{DatabaseDriver: DriverGorm, KMSMasterKey: master, KMSKeyVersion: 1}).Validate(); err != nil {
		t.Errorf("version 1 with master key should validate: %v", err)
	}
}

func TestWarningsCredentialKeyOverlap(t *testing.T) {
	const master = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	has := func(ws []string, sub string) bool {
		for _, w := range ws {
			if strings.Contains(w, sub) {
				return true
			}
		}
		return false
	}
	// Only the master key set: no overlap warning.
	if has((Config{KMSMasterKey: master}).Warnings(), "both ACCESS_KMS_MASTER_KEY") {
		t.Error("master-key-only should not warn about overlap")
	}
	// Only the static DEK set: no overlap warning.
	if has((Config{CredentialDEK: master}).Warnings(), "both ACCESS_KMS_MASTER_KEY") {
		t.Error("DEK-only should not warn about overlap")
	}
	// Both set: re-seal migration footgun warning surfaces.
	if !has((Config{KMSMasterKey: master, CredentialDEK: master}).Warnings(), "both ACCESS_KMS_MASTER_KEY") {
		t.Error("both keys set should warn about the re-seal migration footgun")
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

func TestTenancyWarnings(t *testing.T) {
	// A well-formed tenancy config (matching the loaded defaults) emits nothing.
	healthy := TenancyConfig{
		DormantIdleThreshold:  14 * 24 * time.Hour,
		ReconcileInterval:     15 * time.Minute,
		ActivityFlushInterval: 60 * time.Second,
		ActivityQueueSize:     8192,
		DefaultTier:           "trial",
	}
	if w := healthy.Warnings(); len(w) != 0 {
		t.Errorf("healthy tenancy config produced warnings: %v", w)
	}

	// Each misconfigured knob that has a safe fallback should surface a warning
	// (so the operator learns the value was overridden) without being fatal.
	bad := TenancyConfig{
		DormantIdleThreshold:  -1, // non-positive idle window
		ReconcileInterval:     0,  // non-positive sweep interval
		ActivityFlushInterval: 60 * time.Second,
		ActivityQueueSize:     -5, // non-positive queue size
	}
	if got := len(bad.Warnings()); got != 3 {
		t.Errorf("bad tenancy config warnings = %d, want 3: %v", got, bad.Warnings())
	}

	// A flush window wider than idle/10 is clamped by SafeThrottle at runtime, so
	// it must be flagged even though every other knob is sane.
	clamped := TenancyConfig{
		DormantIdleThreshold:  100 * time.Minute,
		ReconcileInterval:     15 * time.Minute,
		ActivityFlushInterval: 30 * time.Minute, // > idle/10 (10m)
		ActivityQueueSize:     8192,
	}
	if got := clamped.Warnings(); len(got) != 1 {
		t.Errorf("over-wide flush window warnings = %v, want exactly 1", got)
	}
}

func TestRateLimitDefaults(t *testing.T) {
	t.Setenv("ACCESS_TENANT_RATE_LIMIT_ENABLED", "")
	t.Setenv("ACCESS_TENANT_RATE_LIMIT_RPS", "")
	t.Setenv("ACCESS_TENANT_RATE_LIMIT_BURST", "")
	cfg := Load()
	if !cfg.RateLimit.Enabled {
		t.Error("RateLimit.Enabled = false, want true by default")
	}
	if cfg.RateLimit.RequestsPerSecond != 50 {
		t.Errorf("RateLimit.RequestsPerSecond = %g, want 50", cfg.RateLimit.RequestsPerSecond)
	}
	if cfg.RateLimit.Burst != 100 {
		t.Errorf("RateLimit.Burst = %d, want 100", cfg.RateLimit.Burst)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("default rate-limit config failed Validate: %v", err)
	}
}

func TestRateLimitLoadOverrides(t *testing.T) {
	t.Setenv("ACCESS_TENANT_RATE_LIMIT_ENABLED", "false")
	t.Setenv("ACCESS_TENANT_RATE_LIMIT_RPS", "12.5")
	t.Setenv("ACCESS_TENANT_RATE_LIMIT_BURST", "30")
	cfg := Load()
	if cfg.RateLimit.Enabled {
		t.Error("RateLimit.Enabled = true, want false when set to false")
	}
	if cfg.RateLimit.RequestsPerSecond != 12.5 {
		t.Errorf("RateLimit.RequestsPerSecond = %g, want 12.5", cfg.RateLimit.RequestsPerSecond)
	}
	if cfg.RateLimit.Burst != 30 {
		t.Errorf("RateLimit.Burst = %d, want 30", cfg.RateLimit.Burst)
	}
}

func TestValidateRateLimit(t *testing.T) {
	base := func() Config {
		return Config{DatabaseDriver: DriverPgx, RateLimit: RateLimitConfig{Enabled: true, RequestsPerSecond: 50, Burst: 100}}
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("healthy enabled rate-limit config failed Validate: %v", err)
	}
	rpsZero := base()
	rpsZero.RateLimit.RequestsPerSecond = 0
	if err := rpsZero.Validate(); err == nil {
		t.Error("Validate accepted RPS=0 while enabled, want rejection")
	}
	burstZero := base()
	burstZero.RateLimit.Burst = 0
	if err := burstZero.Validate(); err == nil {
		t.Error("Validate accepted Burst=0 while enabled, want rejection")
	}
	// Disabled limiter: bad values are inert and must not fail the boot.
	disabled := Config{DatabaseDriver: DriverPgx, RateLimit: RateLimitConfig{Enabled: false, RequestsPerSecond: 0, Burst: 0}}
	if err := disabled.Validate(); err != nil {
		t.Errorf("disabled limiter with zero values failed Validate: %v", err)
	}
}

func TestGetFloatParsing(t *testing.T) {
	// Unset → default.
	t.Setenv("ACCESS_TENANT_RATE_LIMIT_RPS", "")
	if got := Load().RateLimit.RequestsPerSecond; got != 50 {
		t.Errorf("unset RPS = %g, want default 50", got)
	}
	// Negative → default (silent, mirroring getInt).
	t.Setenv("ACCESS_TENANT_RATE_LIMIT_RPS", "-3")
	if got := Load().RateLimit.RequestsPerSecond; got != 50 {
		t.Errorf("negative RPS = %g, want default 50", got)
	}
	// Parseable 0 → returned as-is so Validate can reject it loudly.
	t.Setenv("ACCESS_TENANT_RATE_LIMIT_RPS", "0")
	if got := Load().RateLimit.RequestsPerSecond; got != 0 {
		t.Errorf("zero RPS = %g, want 0 (passed through to Validate)", got)
	}
}
