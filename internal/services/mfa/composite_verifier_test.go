package mfa

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// recordingVerifier records whether it was called and returns a configured
// result, so dispatch routing can be asserted without real crypto.
type recordingVerifier struct {
	called bool
	err    error
}

func (r *recordingVerifier) VerifyStepUp(_ context.Context, _ uuid.UUID, _, _ string, _ []byte) error {
	r.called = true
	return r.err
}

func TestCompositeDispatchTOTP(t *testing.T) {
	wa := &recordingVerifier{}
	tp := &recordingVerifier{}
	c := NewCompositeMFAVerifier(wa, tp)
	if err := c.VerifyStepUp(context.Background(), uuid.New(), "u", "scope", []byte("123456")); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !tp.called {
		t.Error("TOTP leg should have been called for a 6-digit code")
	}
	if wa.called {
		t.Error("WebAuthn leg must NOT be called for a recognised TOTP code (no cross-route)")
	}
}

func TestCompositeDispatchWebAuthn(t *testing.T) {
	wa := &recordingVerifier{}
	tp := &recordingVerifier{}
	c := NewCompositeMFAVerifier(wa, tp)
	assertion := []byte(`{"authenticatorData":"abc","clientDataJSON":"def"}`)
	if err := c.VerifyStepUp(context.Background(), uuid.New(), "u", "scope", assertion); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !wa.called {
		t.Error("WebAuthn leg should have been called for a WebAuthn assertion")
	}
	if tp.called {
		t.Error("TOTP leg must NOT be called for a recognised WebAuthn assertion")
	}
}

// TestCompositeUnrecognisedFallback proves an unrecognised payload tries
// WebAuthn first then falls back to TOTP.
func TestCompositeUnrecognisedFallback(t *testing.T) {
	wa := &recordingVerifier{err: errors.New("not a webauthn assertion")}
	tp := &recordingVerifier{}
	c := NewCompositeMFAVerifier(wa, tp)
	// 8 chars, not JSON, not a 6-digit code → unrecognised.
	if err := c.VerifyStepUp(context.Background(), uuid.New(), "u", "scope", []byte("abcd1234")); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !wa.called || !tp.called {
		t.Errorf("both legs should be tried on unrecognised input: wa=%v tp=%v", wa.called, tp.called)
	}
}

func TestCompositeTOTPWithNoTOTPLegFallsThrough(t *testing.T) {
	// 6-digit code but only a WebAuthn leg wired: routing recognises TOTP, but
	// with no TOTP leg it falls through to the WebAuthn attempt.
	wa := &recordingVerifier{}
	c := NewCompositeMFAVerifier(wa, nil)
	if err := c.VerifyStepUp(context.Background(), uuid.New(), "u", "scope", []byte("123456")); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !wa.called {
		t.Error("WebAuthn leg should be the fallback when no TOTP leg is wired")
	}
}

func TestCompositeBothNilFailsClosed(t *testing.T) {
	c := NewCompositeMFAVerifier(nil, nil)
	if err := c.VerifyStepUp(context.Background(), uuid.New(), "u", "scope", []byte("123456")); !errors.Is(err, ErrMFAFailed) {
		t.Fatalf("err = %v, want ErrMFAFailed", err)
	}
}

func TestCompositeEmptyAssertionFailsClosed(t *testing.T) {
	c := NewCompositeMFAVerifier(&recordingVerifier{}, &recordingVerifier{})
	if err := c.VerifyStepUp(context.Background(), uuid.New(), "u", "scope", nil); !errors.Is(err, ErrMFAFailed) {
		t.Fatalf("err = %v, want ErrMFAFailed", err)
	}
}

func TestIsTOTPCodeAndWebAuthnDetection(t *testing.T) {
	if !isTOTPCode([]byte("000000")) || !isTOTPCode([]byte("  123456 ")) {
		t.Error("valid 6-digit codes should be detected")
	}
	if isTOTPCode([]byte("12345")) || isTOTPCode([]byte("12345a")) {
		t.Error("non 6-digit strings should not be detected as TOTP")
	}
	if !isWebAuthnAssertion([]byte(`{"response":{}}`)) {
		t.Error("JSON with response field should be detected as WebAuthn")
	}
	if isWebAuthnAssertion([]byte(`{"foo":"bar"}`)) || isWebAuthnAssertion([]byte("notjson")) {
		t.Error("non-assertion JSON / non-JSON should not be detected as WebAuthn")
	}
}
