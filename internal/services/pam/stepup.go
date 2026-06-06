package pam

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/iamcore"
)

// ErrStepUpRequired is returned when a sensitive PAM operation (secret reveal,
// connect to an MFA-gated target) needs a fresh step-up assertion the caller
// has not supplied.
var ErrStepUpRequired = errors.New("pam: step-up MFA required")

// ErrStepUpInvalid is returned when a presented step-up token fails validation:
// bad signature, wrong subject/tenant, no MFA claim, or stale beyond the
// recency window.
var ErrStepUpInvalid = errors.New("pam: step-up MFA assertion invalid")

// TokenValidator is the slice of iamcore.Validator the gate depends on. The
// interface lets tests inject an in-memory validator (fake JWKS, signed test
// tokens) without a live iam-core.
type TokenValidator interface {
	Validate(tokenString string) (*iamcore.Claims, error)
}

// StepUpGate enforces step-up MFA on sensitive PAM operations following the
// shared iam-core contract: there is NO /auth/mfa/verify endpoint, so the
// caller drives a fresh OIDC re-auth (prompt=login requesting MFA) out of band
// and presents the resulting access token here. The gate validates that token,
// confirms it carries an MFA-satisfied claim, is bound to the same user and
// tenant as the session, and was issued recently enough to count as a genuine
// step-up rather than a replay of the original login.
//
// It is fail-closed: a missing token, a token without an MFA claim, a
// subject/tenant mismatch, or an assertion older than the recency window all
// deny the operation.
type StepUpGate struct {
	validator TokenValidator
	maxAge    time.Duration
	now       func() time.Time
}

// NewStepUpGate wires a gate. maxAge is how recently the step-up token must have
// been authenticated (its auth_time/iat) to be accepted; <= 0 selects 5 minutes.
func NewStepUpGate(validator TokenValidator, maxAge time.Duration) *StepUpGate {
	if maxAge <= 0 {
		maxAge = 5 * time.Minute
	}
	return &StepUpGate{validator: validator, maxAge: maxAge, now: time.Now}
}

// SetClock overrides the time source (tests).
func (g *StepUpGate) SetClock(now func() time.Time) {
	if now != nil {
		g.now = now
	}
}

// Enabled reports whether the gate can enforce step-up. A gate with no
// validator cannot, and callers MUST treat that as fail-closed for MFA-gated
// targets (refuse the operation) rather than silently skipping the check.
func (g *StepUpGate) Enabled() bool { return g != nil && g.validator != nil }

// Require validates a step-up assertion for (subject, iamTenantID). stepUpToken
// is the access token from the fresh MFA-satisfied re-auth. It returns nil only
// when the token is valid, MFA-satisfied, bound to the same subject and tenant,
// and authenticated within the recency window.
func (g *StepUpGate) Require(subject, iamTenantID, stepUpToken string) error {
	if !g.Enabled() {
		return fmt.Errorf("%w: step-up gate not configured", ErrStepUpInvalid)
	}
	if stepUpToken == "" {
		return ErrStepUpRequired
	}
	claims, err := g.validator.Validate(stepUpToken)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStepUpInvalid, err)
	}
	if subject != "" && claims.Subject != subject {
		return fmt.Errorf("%w: token subject %q does not match session subject %q", ErrStepUpInvalid, claims.Subject, subject)
	}
	if iamTenantID != "" && claims.TenantID != iamTenantID {
		return fmt.Errorf("%w: token tenant does not match session tenant", ErrStepUpInvalid)
	}
	if !claims.MFASatisfied {
		return fmt.Errorf("%w: token does not assert MFA", ErrStepUpInvalid)
	}
	authAt, ok := authTime(claims)
	if !ok {
		return fmt.Errorf("%w: token has no auth_time/iat to bound recency", ErrStepUpInvalid)
	}
	if age := g.now().Sub(authAt); age > g.maxAge {
		return fmt.Errorf("%w: step-up assertion is stale (%s old, max %s)", ErrStepUpInvalid, age.Truncate(time.Second), g.maxAge)
	}
	return nil
}

// authTime extracts the moment the step-up session authenticated, preferring
// the OIDC "auth_time" claim and falling back to "iat". The bool is false when
// neither is present, which the caller treats as fail-closed.
func authTime(c *iamcore.Claims) (time.Time, bool) {
	if c.Raw != nil {
		if t, ok := unixClaim(c.Raw["auth_time"]); ok {
			return t, true
		}
		if t, ok := unixClaim(c.Raw["iat"]); ok {
			return t, true
		}
	}
	return time.Time{}, false
}

// unixClaim coerces a JSON numeric claim (float64 after encoding/json) or an
// integer to a time.Time. Returns false for any other type or a non-positive
// value.
func unixClaim(v any) (time.Time, bool) {
	switch n := v.(type) {
	case float64:
		if n <= 0 {
			return time.Time{}, false
		}
		return time.Unix(int64(n), 0), true
	case int64:
		if n <= 0 {
			return time.Time{}, false
		}
		return time.Unix(n, 0), true
	case json.Number:
		i, err := n.Int64()
		if err != nil || i <= 0 {
			return time.Time{}, false
		}
		return time.Unix(i, 0), true
	default:
		return time.Time{}, false
	}
}
