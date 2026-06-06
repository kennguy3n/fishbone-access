// Package iamcore integrates ShieldNet Access with uneycom/iam-core, the
// upstream OAuth2/OIDC identity provider. This file implements access-token
// validation: signatures are checked against iam-core's JWKS endpoint
// (/oauth2/jwks) and the standard registered claims (iss/aud/exp/nbf) are
// enforced. Application claims — the iam-core user id (sub), tenant id, roles,
// scopes and MFA state — are extracted into a strongly-typed Claims value the
// middleware injects into the request context.
//
// See docs/iam-core-integration.md for the authoritative contract. There is
// deliberately NO Keycloak here: iam-core is the only identity provider.
package iamcore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"

	"github.com/kennguy3n/fishbone-access/internal/config"
)

// ErrInvalidToken is the single sentinel callers match on; the underlying
// cause is wrapped for logs but never leaked to API clients.
var ErrInvalidToken = errors.New("iamcore: invalid token")

// Claims is the validated, application-level view of an iam-core access token.
type Claims struct {
	// Subject is the iam-core user_id (the `sub` claim).
	Subject string
	// TenantID is the iam-core tenant the caller is acting within.
	TenantID string
	// Roles and Scopes are authorization inputs extracted from the token.
	Roles  []string
	Scopes []string
	// MFASatisfied reports whether the session behind this token completed
	// multi-factor authentication, derived from the `amr` array (contains
	// "mfa"/"otp"/"hwk") or a boolean `mfa` claim.
	MFASatisfied bool
	// ExpiresAt is the token expiry.
	ExpiresAt time.Time
	// Raw exposes the full claim set for callers that need a non-standard
	// claim not promoted to a field above.
	Raw map[string]any
}

// Validator validates iam-core access tokens against a cached JWKS.
type Validator struct {
	kf       keyfunc.Keyfunc
	issuer   string
	audience string
	parser   *jwt.Parser
}

// NewValidator builds a Validator that fetches and caches iam-core's JWKS from
// cfg.ResolvedJWKSURL(). The JWKS is refreshed in the background and re-fetched
// on an unknown key id, so iam-core key rotation needs no redeploy.
func NewValidator(ctx context.Context, cfg config.IAMCoreConfig) (*Validator, error) {
	if !cfg.Configured() {
		return nil, errors.New("iamcore: not configured (issuer/JWKS missing)")
	}
	kf, err := keyfunc.NewDefaultCtx(ctx, []string{cfg.ResolvedJWKSURL()})
	if err != nil {
		return nil, fmt.Errorf("iamcore: build keyfunc from %s: %w", cfg.ResolvedJWKSURL(), err)
	}
	return newValidator(kf, cfg.Issuer, cfg.Audience), nil
}

// newValidator is the shared constructor used by NewValidator and by tests that
// inject an in-memory keyfunc.
func newValidator(kf keyfunc.Keyfunc, issuer, audience string) *Validator {
	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384"}),
		jwt.WithExpirationRequired(),
	}
	if issuer != "" {
		opts = append(opts, jwt.WithIssuer(issuer))
	}
	if audience != "" {
		opts = append(opts, jwt.WithAudience(audience))
	}
	return &Validator{
		kf:       kf,
		issuer:   issuer,
		audience: audience,
		parser:   jwt.NewParser(opts...),
	}
}

// Validate verifies the signature and registered claims of tokenString and
// returns the extracted application claims. Any failure maps to ErrInvalidToken
// (wrapped) so handlers can respond 401 without branching on the cause.
func (v *Validator) Validate(tokenString string) (*Claims, error) {
	mc := jwt.MapClaims{}
	if _, err := v.parser.ParseWithClaims(tokenString, mc, v.kf.Keyfunc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	return claimsFromMap(mc)
}

func claimsFromMap(mc jwt.MapClaims) (*Claims, error) {
	sub, _ := mc["sub"].(string)
	if sub == "" {
		return nil, fmt.Errorf("%w: missing sub", ErrInvalidToken)
	}
	c := &Claims{
		Subject:      sub,
		TenantID:     firstStringClaim(mc, "tenant_id", "tid"),
		Roles:        stringSliceClaim(mc, "roles"),
		Scopes:       scopeClaim(mc),
		MFASatisfied: mfaFromClaims(mc),
		Raw:          map[string]any(mc),
	}
	if exp, err := mc.GetExpirationTime(); err == nil && exp != nil {
		c.ExpiresAt = exp.Time
	}
	return c, nil
}

func firstStringClaim(mc jwt.MapClaims, keys ...string) string {
	for _, k := range keys {
		if s, ok := mc[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// stringSliceClaim reads a claim that may be a JSON array of strings or a
// single string.
func stringSliceClaim(mc jwt.MapClaims, key string) []string {
	switch v := mc[key].(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	default:
		return nil
	}
}

// scopeClaim reads the OAuth2 `scope` claim (space-delimited string per
// RFC 8693) or a `scp` array.
func scopeClaim(mc jwt.MapClaims) []string {
	if s, ok := mc["scope"].(string); ok && s != "" {
		return splitSpace(s)
	}
	return stringSliceClaim(mc, "scp")
}

func splitSpace(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ' ' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// mfaFromClaims derives MFA satisfaction from a boolean `mfa` claim or from the
// `amr` (Authentication Methods References, RFC 8176) array.
func mfaFromClaims(mc jwt.MapClaims) bool {
	if b, ok := mc["mfa"].(bool); ok && b {
		return true
	}
	for _, amr := range stringSliceClaim(mc, "amr") {
		switch amr {
		case "mfa", "otp", "hwk", "swk", "totp", "fido", "webauthn":
			return true
		}
	}
	return false
}
