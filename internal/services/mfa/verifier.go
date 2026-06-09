// Package mfa is the step-up multi-factor verification layer guarding the
// highest-risk Access actions (policy promotion, PAM connect/takeover,
// compliance export). It is consumed by the RequireStepUpMFA middleware and any
// service that must re-challenge a human immediately before an irreversible or
// privilege-escalating effect.
//
// Two production verifiers live here:
//
//   - TOTPMFAVerifier: validates an RFC 6238 code against the user's enrolled
//     secret AND enforces single-use (replay prevention) by claiming the code
//     in pam_totp_used_codes.
//   - CompositeMFAVerifier: dispatches on the assertion shape so one gate can
//     accept either a WebAuthn assertion (if/when a WebAuthn verifier is wired)
//     or a TOTP code, without the caller switching on credential type.
//
// Every verifier is workspace-scoped: the (workspace_id, user_id) pair keys
// both the secret lookup and the replay claim, so a code or secret never leaks
// across tenants even if user ids collide between workspaces.
package mfa

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

// MFAVerifier is the narrow contract the step-up gate depends on. assertion is
// the opaque wire payload submitted by the user agent (a WebAuthn assertion
// JSON blob, or a 6-digit TOTP code); the interface treats it as bytes so
// callers never switch on credential type. scope names the operation being
// authorized (e.g. "policy.promote", "pam.connect") and is recorded for audit;
// it does not affect TOTP validation since RFC 6238 codes are not scope-bound.
//
// workspaceID scopes the verification to a single tenant. Implementations MUST
// fail closed (return a non-nil error) on any ambiguity — a missing secret, an
// invalid assertion, a replay, or an infrastructure error all deny.
type MFAVerifier interface {
	VerifyStepUp(ctx context.Context, workspaceID uuid.UUID, userID, scope string, assertion []byte) error
}

// Sentinel MFA errors. The handler/middleware layer maps these to HTTP status
// codes (ErrMFARequired -> 400, ErrMFAFailed -> 403).
var (
	// ErrMFARequired indicates no MFA assertion was supplied. The verifiers
	// never return this (they receive bytes); the middleware returns it when
	// the request carries no assertion to verify.
	ErrMFARequired = errors.New("mfa: step-up assertion required")

	// ErrMFAFailed indicates the supplied assertion did not verify — bad code,
	// no enrolled secret, or a replay of an already-used code. The client only
	// learns it failed; the specific cause is logged server-side, never echoed.
	ErrMFAFailed = errors.New("mfa: step-up verification failed")
)
