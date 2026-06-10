//go:build production

package iamcore

import "errors"

// ErrDevAuthDisabled is returned by NewDevValidator in production builds. The
// HMAC dev validator (devauth.go) is excluded from production binaries by build
// tag, so this stub guarantees a production build neither contains nor can
// construct a shared-secret token validator. Identity in production is
// terminated exclusively against iam-core's JWKS (validator.go).
var ErrDevAuthDisabled = errors.New("iamcore: dev HMAC auth is not available in production builds")

// DevValidator is an empty type in production so references still compile, but
// it can never be constructed.
type DevValidator struct{}

// Validate always fails: a production DevValidator can never be instantiated.
func (*DevValidator) Validate(string) (*Claims, error) { return nil, ErrDevAuthDisabled }

// NewDevValidator always errors in production builds.
func NewDevValidator(_, _, _ string) (*DevValidator, error) { return nil, ErrDevAuthDisabled }
