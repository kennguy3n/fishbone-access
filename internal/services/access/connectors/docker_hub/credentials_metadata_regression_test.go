package docker_hub

import (
	"context"
	"strings"
	"testing"
)

// Regression: GetCredentialsMetadata must never expose the plaintext secret.
// shortToken previously returned its input verbatim for inputs of 8 chars or
// fewer, so a short password leaked in full via `password_short` (which feeds
// admin UIs, expiry alerts, and logs).
func TestGetCredentialsMetadata_DoesNotLeakShortPassword(t *testing.T) {
	const pw = "s3cret" // 6 chars -> hit the old <=8 verbatim branch
	c := New()
	meta, err := c.GetCredentialsMetadata(context.Background(), validConfig(),
		map[string]interface{}{"username": "alice123", "password": pw})
	if err != nil {
		t.Fatalf("GetCredentialsMetadata: %v", err)
	}
	if got, _ := meta["password_short"].(string); strings.Contains(got, pw) {
		t.Fatalf("password_short = %q leaks the plaintext password %q", got, pw)
	}
}

func TestShortToken_MasksShortSecret(t *testing.T) {
	for _, s := range []string{"a", "secret", "12345678"} {
		if got := shortToken(s); got == s {
			t.Fatalf("shortToken(%q) = %q; short secret returned verbatim", s, got)
		}
	}
	if got := shortToken(""); got != "" {
		t.Fatalf("shortToken(\"\") = %q; want \"\"", got)
	}
	if got := shortToken("abcdefghij"); got != "abcd...ghij" {
		t.Fatalf("shortToken(long) = %q; want masked prefix/suffix", got)
	}
}
