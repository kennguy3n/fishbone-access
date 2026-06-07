package sumo_logic

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// TestFormatErrorBody_ScrubsProxyHTML verifies that a reverse-proxy
// error page is not echoed verbatim into the error surface, so trace
// IDs, cookie names, and internal hostnames cannot leak into operator
// dashboards/logs.
func TestFormatErrorBody_ScrubsProxyHTML(t *testing.T) {
	body := []byte("<html><head><title>502 Bad Gateway</title></head>" +
		"<body>x-trace-id=abc123 set-cookie: session=topsecret " +
		"upstream=ip-10-0-0-5.internal</body></html>")
	out := formatErrorBody(body)
	for _, leak := range []string{"abc123", "topsecret", "ip-10-0-0-5"} {
		if strings.Contains(out, leak) {
			t.Fatalf("formatErrorBody leaked proxy metadata %q: %q", leak, out)
		}
	}
	if !strings.Contains(out, "kind=html") {
		t.Errorf("formatErrorBody should classify a proxy page as html: %q", out)
	}
}

// TestFormatErrorBody_PreservesJSONEnvelope verifies the provider's own
// structured JSON error is preserved so operators keep actionable detail.
func TestFormatErrorBody_PreservesJSONEnvelope(t *testing.T) {
	body := []byte(`{"error":"invalid_token","message":"token expired"}`)
	if got := formatErrorBody(body); got != string(body) {
		t.Errorf("formatErrorBody should preserve JSON error envelope; got %q", got)
	}
}

// TestFormatErrorBody_Empty verifies the empty-body sentinel.
func TestFormatErrorBody_Empty(t *testing.T) {
	if got := formatErrorBody(nil); got != "(empty)" {
		t.Errorf("formatErrorBody(nil) = %q; want (empty)", got)
	}
}

// TestFormatErrorBody_TruncatesJSONAtRuneBoundary verifies an oversized
// JSON body is capped on a valid UTF-8 rune boundary (downstream log
// pipelines reject invalid UTF-8).
func TestFormatErrorBody_TruncatesJSONAtRuneBoundary(t *testing.T) {
	const ellipsis = "\u2026" // 0xE2 0x80 0xA6
	prefix := "{" + strings.Repeat(" ", errorBodyJSONCap-2)
	body := []byte(prefix + ellipsis + strings.Repeat(ellipsis, 100))
	if !utf8.Valid(body) {
		t.Fatalf("test fixture is not valid UTF-8")
	}
	if utf8.RuneStart(body[errorBodyJSONCap]) {
		t.Fatalf("fixture does not exercise the boundary case")
	}
	out := formatErrorBody(body)
	if !utf8.ValidString(out) {
		t.Errorf("output is not valid UTF-8: %q", out)
	}
	if !strings.HasSuffix(out, " …(truncated)") {
		t.Errorf("output missing truncation marker")
	}
	visible := strings.TrimSuffix(out, " …(truncated)")
	if !utf8.ValidString(visible) {
		t.Errorf("visible prefix is not valid UTF-8")
	}
	if len(visible) > errorBodyJSONCap {
		t.Errorf("visible len = %d; want <= cap %d", len(visible), errorBodyJSONCap)
	}
}
