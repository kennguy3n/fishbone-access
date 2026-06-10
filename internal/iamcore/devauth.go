//go:build !production

package iamcore

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// DevValidator validates symmetric (HMAC-SHA256) bearer tokens signed with a
// shared secret, and is the developer-convenience identity path: it lets an
// operator mint and verify iam-core-shaped access tokens with a single
// AUTH_JWT_SECRET, without standing up an iam-core instance, JWKS endpoint or
// OAuth2 dance. The seed/capture blog harnesses (blog/harness/*) use it to
// drive the real control-plane API end-to-end against a local Postgres.
//
// It is compiled ONLY into non-production builds (the //go:build !production
// tag above). The production stub in devauth_prod.go is linked instead, so a
// production binary contains no HMAC verification code at all and cannot accept
// an HMAC-signed token even if one is presented — identity in production is
// terminated against iam-core's JWKS (validator.go). cmd/ztna-api additionally
// refuses to enable this path when ACCESS_ENV is a production label, so the
// developer path is unreachable in production both by construction (build tag)
// and by configuration guard. See SECURITY semantics mirrored from the sibling
// ShieldNet Gateway control plane.
//
// The extracted Claims are identical in shape and semantics to those the JWKS
// Validator produces (both call extractClaims), so every downstream gate —
// tenant resolution, RBAC, the MFA claim gate — behaves the same regardless of
// which validator verified the token.
type DevValidator struct {
	secret []byte
	parser *jwt.Parser
	issuer string
}

// NewDevValidator builds a DevValidator over secret. issuer/audience are
// enforced only when non-empty (an empty issuer/audience disables that
// registered-claim check), matching how the JWKS validator treats them; the
// HS256 signing method and a present expiry are always required, so an
// unsigned/none-alg or never-expiring token is rejected. A blank secret is a
// misconfiguration and is refused rather than verifying every token against an
// empty key.
func NewDevValidator(secret, issuer, audience string) (*DevValidator, error) {
	if secret == "" {
		return nil, errors.New("iamcore: dev HMAC validator requires a non-empty secret")
	}
	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithExpirationRequired(),
	}
	if issuer != "" {
		opts = append(opts, jwt.WithIssuer(issuer))
	}
	if audience != "" {
		opts = append(opts, jwt.WithAudience(audience))
	}
	return &DevValidator{
		secret: []byte(secret),
		parser: jwt.NewParser(opts...),
		issuer: issuer,
	}, nil
}

// Validate verifies the HMAC signature and registered claims of tokenString and
// returns the extracted application claims. Any failure maps to ErrInvalidToken
// (wrapped) so the auth middleware responds 401 without branching on the cause,
// exactly like the JWKS Validator.
func (d *DevValidator) Validate(tokenString string) (*Claims, error) {
	mc := jwt.MapClaims{}
	_, err := d.parser.ParseWithClaims(tokenString, mc, func(t *jwt.Token) (any, error) {
		// Defence-in-depth alongside WithValidMethods: reject any token whose
		// alg is not HMAC so an RS256/none token can never be verified against
		// the shared secret as if it were the HMAC key.
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("iamcore: unexpected signing method %q", t.Method.Alg())
		}
		return d.secret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	return extractClaims(mc, d.issuer)
}
