// Package config loads the ShieldNet Access platform configuration from the
// process environment. Every binary (ztna-api, access-connector-worker,
// pam-gateway) calls Load exactly once at boot and threads the returned Config
// through its service constructors.
//
// The configuration is intentionally env-driven (12-factor) so the same image
// runs across the three cost-optimised deployment tiers (single-server
// docker-compose, managed K8s, full production) with nothing but environment
// changes.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the fully-resolved platform configuration.
type Config struct {
	// Env is the deployment environment label ("dev", "staging", "prod").
	Env string
	// HTTPAddr is the listen address for the ztna-api HTTP server.
	HTTPAddr string
	// DatabaseURL is the Postgres DSN. When empty the binary boots in
	// degraded mode (handlers that need the DB return 503) so `go run`
	// works without provisioning Postgres.
	DatabaseURL string
	// RedisURL is the Redis connection URL used for the worker queue and
	// rate limiting. Optional in degraded mode.
	RedisURL string
	// CredentialDEK is the base64-encoded 32-byte AES-256 key used to seal
	// connector secrets at rest. When empty the binary refuses to persist
	// secrets (fails closed) rather than storing plaintext.
	CredentialDEK string

	// IAMCore holds the iam-core identity-provider integration settings.
	IAMCore IAMCoreConfig

	// ShutdownTimeout bounds graceful HTTP shutdown.
	ShutdownTimeout time.Duration
}

// IAMCoreConfig configures integration with uneycom/iam-core, the upstream
// OAuth2/OIDC identity provider. See docs/iam-core-integration.md.
type IAMCoreConfig struct {
	// Issuer is the iam-core base URL. It hosts /oauth2/* and
	// /.well-known/* — e.g. https://iam.example.com.
	Issuer string
	// JWKSURL is the JWKS endpoint used to validate access-token
	// signatures. Defaults to Issuer + "/oauth2/jwks" when unset.
	JWKSURL string
	// DiscoveryURL is the OIDC discovery document. Defaults to
	// Issuer + "/.well-known/openid-configuration" when unset.
	DiscoveryURL string
	// ClientID / ClientSecret identify this product as a confidential
	// OAuth2 client (used for the SSO code flow and for minting a
	// client_credentials token against the management audience).
	ClientID     string
	ClientSecret string
	// Audience is the expected `aud` claim on access tokens issued for
	// this product.
	Audience string
	// ManagementBaseURL hosts the /api/v1/management/* API. Defaults to
	// Issuer when unset.
	ManagementBaseURL string
}

// Configured reports whether the minimum iam-core settings are present for
// JWT validation (issuer + a resolvable JWKS endpoint).
func (c IAMCoreConfig) Configured() bool {
	return c.Issuer != "" && c.ResolvedJWKSURL() != ""
}

// ManagementConfigured reports whether the Management API client can actually
// authenticate. The management calls (e.g. BlockUser for the leaver kill
// switch) mint a client_credentials token, which needs both ClientID and
// ClientSecret in addition to the issuer. Wiring a management client without
// these would produce a client that fails every call, so the caller should
// leave the dependent feature unwired (reporting "skipped") when this is false.
func (c IAMCoreConfig) ManagementConfigured() bool {
	return c.Configured() && c.ClientID != "" && c.ClientSecret != ""
}

// ResolvedJWKSURL returns JWKSURL, deriving it from Issuer when unset.
func (c IAMCoreConfig) ResolvedJWKSURL() string {
	if c.JWKSURL != "" {
		return c.JWKSURL
	}
	if c.Issuer == "" {
		return ""
	}
	return strings.TrimRight(c.Issuer, "/") + "/oauth2/jwks"
}

// ResolvedDiscoveryURL returns DiscoveryURL, deriving it from Issuer when unset.
func (c IAMCoreConfig) ResolvedDiscoveryURL() string {
	if c.DiscoveryURL != "" {
		return c.DiscoveryURL
	}
	if c.Issuer == "" {
		return ""
	}
	return strings.TrimRight(c.Issuer, "/") + "/.well-known/openid-configuration"
}

// ResolvedManagementBaseURL returns ManagementBaseURL, deriving it from Issuer
// when unset.
func (c IAMCoreConfig) ResolvedManagementBaseURL() string {
	if c.ManagementBaseURL != "" {
		return strings.TrimRight(c.ManagementBaseURL, "/")
	}
	return strings.TrimRight(c.Issuer, "/")
}

// Load reads the configuration from the environment, applying defaults. It
// never reads files and never panics: callers boot in degraded mode when
// optional dependencies are absent.
func Load() Config {
	return Config{
		Env:             getEnv("ACCESS_ENV", "dev"),
		HTTPAddr:        getEnv("ACCESS_HTTP_ADDR", ":8080"),
		DatabaseURL:     os.Getenv("ACCESS_DATABASE_URL"),
		RedisURL:        os.Getenv("ACCESS_REDIS_URL"),
		CredentialDEK:   os.Getenv("ACCESS_CREDENTIAL_DEK"),
		ShutdownTimeout: getDuration("ACCESS_SHUTDOWN_TIMEOUT", 10*time.Second),
		IAMCore: IAMCoreConfig{
			Issuer:            os.Getenv("IAM_CORE_ISSUER"),
			JWKSURL:           os.Getenv("IAM_CORE_JWKS_URL"),
			DiscoveryURL:      os.Getenv("IAM_CORE_OIDC_DISCOVERY"),
			ClientID:          os.Getenv("IAM_CORE_CLIENT_ID"),
			ClientSecret:      os.Getenv("IAM_CORE_CLIENT_SECRET"),
			Audience:          os.Getenv("IAM_CORE_AUDIENCE"),
			ManagementBaseURL: os.Getenv("IAM_CORE_MGMT_BASE_URL"),
		},
	}
}

// DatabaseConfigured reports whether a Postgres DSN was supplied.
func (c Config) DatabaseConfigured() bool { return c.DatabaseURL != "" }

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	// Bare integer is interpreted as seconds.
	if n, err := strconv.Atoi(v); err == nil {
		return time.Duration(n) * time.Second
	}
	return def
}

// String renders a redacted, log-safe summary of the configuration. Secrets
// (ClientSecret, CredentialDEK) are never included.
func (c Config) String() string {
	return fmt.Sprintf(
		"Config{env=%s http=%s db=%t redis=%t dek=%t iamcore=%t issuer=%q}",
		c.Env, c.HTTPAddr, c.DatabaseConfigured(), c.RedisURL != "",
		c.CredentialDEK != "", c.IAMCore.Configured(), c.IAMCore.Issuer,
	)
}
