package mfa

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/google/uuid"
)

// CompositeMFAVerifier routes a step-up assertion to the verifier matching its
// credential type, so one gate accepts either a WebAuthn assertion or a TOTP
// code without the caller switching on type. The credential type is detected
// from the assertion bytes:
//
//   - WebAuthn assertions are JSON objects carrying a "response",
//     "authenticatorData", or "clientDataJSON" field (W3C WebAuthn §5.8.1).
//   - TOTP codes are 6-digit numeric strings.
//
// fishbone-access does not yet ship a WebAuthn verifier, so the webauthn leg is
// typically nil today; the composite still routes TOTP correctly and is ready
// to gain a WebAuthn leg with no call-site change. With both legs nil,
// VerifyStepUp always returns ErrMFAFailed (fail closed).
type CompositeMFAVerifier struct {
	webauthn MFAVerifier
	totp     MFAVerifier
}

// NewCompositeMFAVerifier constructs a composite verifier. Either leg may be
// nil — the composite skips a nil leg and tries the other. Both nil yields a
// verifier that always fails closed.
func NewCompositeMFAVerifier(webauthn, totp MFAVerifier) *CompositeMFAVerifier {
	return &CompositeMFAVerifier{webauthn: webauthn, totp: totp}
}

// VerifyStepUp detects the credential type and dispatches. Routing is
// intentionally asymmetric:
//
//   - Recognised WebAuthn assertion → WebAuthn leg only (no TOTP fallback): a
//     6-digit code must never be accepted where a phishing-resistant WebAuthn
//     assertion was presented, and vice-versa, so a recognised type never
//     cross-routes to the weaker factor.
//   - Recognised TOTP code → TOTP leg only.
//   - Unrecognised format → try WebAuthn, then fall back to TOTP, so a
//     non-standard client serialization still has a chance to verify against
//     whatever legs are wired.
func (c *CompositeMFAVerifier) VerifyStepUp(ctx context.Context, workspaceID uuid.UUID, userID, scope string, assertion []byte) error {
	if len(assertion) == 0 {
		return ErrMFAFailed
	}

	if isWebAuthnAssertion(assertion) && c.webauthn != nil {
		return c.webauthn.VerifyStepUp(ctx, workspaceID, userID, scope, assertion)
	}

	if isTOTPCode(assertion) && c.totp != nil {
		return c.totp.VerifyStepUp(ctx, workspaceID, userID, scope, assertion)
	}

	// Unrecognised format: try WebAuthn first (it strictly validates and
	// rejects non-assertions quickly), then fall back to TOTP.
	if c.webauthn != nil {
		if err := c.webauthn.VerifyStepUp(ctx, workspaceID, userID, scope, assertion); err == nil {
			return nil
		}
	}
	if c.totp != nil {
		return c.totp.VerifyStepUp(ctx, workspaceID, userID, scope, assertion)
	}

	return ErrMFAFailed
}

// isWebAuthnAssertion reports whether the bytes look like a JSON WebAuthn
// assertion. Detection is intentionally lenient (JSON object + a known field
// name) rather than a full deserialization so routing stays cheap; the chosen
// leg performs the real cryptographic verification.
func isWebAuthnAssertion(data []byte) bool {
	s := strings.TrimSpace(string(data))
	if len(s) == 0 || s[0] != '{' {
		return false
	}
	var probe map[string]json.RawMessage
	if json.Unmarshal(data, &probe) != nil {
		return false
	}
	_, hasResponse := probe["response"]
	_, hasAuthData := probe["authenticatorData"]
	_, hasClientData := probe["clientDataJSON"]
	return hasResponse || hasAuthData || hasClientData
}

// isTOTPCode reports whether the bytes look like a 6-digit TOTP code (optional
// surrounding whitespace).
func isTOTPCode(data []byte) bool {
	s := strings.TrimSpace(string(data))
	if len(s) != 6 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

var _ MFAVerifier = (*CompositeMFAVerifier)(nil)
