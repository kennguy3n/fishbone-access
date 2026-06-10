package middleware

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
	"github.com/kennguy3n/fishbone-access/internal/services/mfa"
)

// StepUpAssertionHeader carries the step-up MFA assertion (a TOTP code, or a
// WebAuthn assertion JSON blob) for the current request. It is a header rather
// than a body field so the gate can verify the assertion without consuming or
// constraining the route's JSON body, and so the same gate composes onto routes
// with differing body shapes.
const StepUpAssertionHeader = "X-MFA-Assertion" //nolint:gosec // HTTP header name, not a credential.

// RequireStepUpMFA returns a middleware that demands a fresh, valid step-up MFA
// assertion for the highest-risk actions (policy promotion, PAM connect /
// takeover, compliance export). It composes with — and does not replace — the
// session-level RequireMFA claim gate: RequireMFA proves the session was
// MFA-authenticated, while this gate proves the human re-asserted possession of
// a factor at the moment of the irreversible effect, and (for TOTP) that the
// code has not been replayed.
//
// It MUST run after Auth → ResolveTenant → RequireTenant and is fail-closed:
//
//  1. No validated claims / empty subject → 401.
//  2. No resolved workspace → 403.
//  3. No verifier wired (missing dependency) → 503: a high-risk route must
//     never silently skip step-up because the verifier was not configured.
//  4. No assertion header → 400 (ErrMFARequired).
//  5. Assertion fails to verify or is a replay → 403 (ErrMFAFailed).
//
// scope names the guarded operation (e.g. "policy.promote") and is passed to
// the verifier for audit correlation.
func RequireStepUpMFA(verifier mfa.MFAVerifier, scope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims := ClaimsFromContext(c)
		if claims == nil || claims.Subject == "" {
			abort(c, http.StatusUnauthorized, "authentication required")
			return
		}
		workspaceID, ok := WorkspaceFromContext(c)
		if !ok {
			abort(c, http.StatusForbidden, "no workspace resolved")
			return
		}
		if verifier == nil {
			// Fail closed: a high-risk action must not proceed without the
			// step-up gate it was configured to require.
			logger.Errorf(c.Request.Context(), "mfa: RequireStepUpMFA invoked with nil verifier scope=%s path=%s", scope, c.FullPath())
			abort(c, http.StatusServiceUnavailable, "step-up verification unavailable")
			return
		}

		assertion := c.GetHeader(StepUpAssertionHeader)
		if assertion == "" {
			abort(c, http.StatusBadRequest, "step-up MFA assertion required")
			return
		}

		err := verifier.VerifyStepUp(c.Request.Context(), workspaceID, claims.Subject, scope, []byte(assertion))
		if err == nil {
			c.Next()
			return
		}
		if errors.Is(err, mfa.ErrMFAFailed) {
			logger.Warnf(c.Request.Context(), "mfa: step-up denied workspace_id=%s user_id=%s scope=%s", workspaceID, claims.Subject, scope)
			abort(c, http.StatusForbidden, "step-up MFA verification failed")
			return
		}
		logger.Errorf(c.Request.Context(), "mfa: step-up verifier error workspace_id=%s user_id=%s scope=%s: %v", workspaceID, claims.Subject, scope, err)
		abort(c, http.StatusServiceUnavailable, "step-up verification unavailable")
	}
}
