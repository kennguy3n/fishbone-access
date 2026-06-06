package docusign_clm

import "testing"

// Regression: shortToken must never return a secret verbatim. It previously
// returned inputs of 8 chars or fewer unredacted, leaking short secrets via
// credential metadata.
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
