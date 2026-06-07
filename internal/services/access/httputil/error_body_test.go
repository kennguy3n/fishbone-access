package httputil

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// TestSafeErrorBody_ScrubsProxyHTML verifies that a reverse-proxy error
// page is not echoed verbatim into the error surface, so trace IDs,
// cookie names, and internal hostnames cannot leak into operator
// dashboards/logs.
func TestSafeErrorBody_ScrubsProxyHTML(t *testing.T) {
	body := []byte("<html><head><title>502 Bad Gateway</title></head>" +
		"<body>x-trace-id=abc123 set-cookie: session=topsecret " +
		"upstream=ip-10-0-0-5.internal</body></html>")
	out := SafeErrorBody(body)
	for _, leak := range []string{"abc123", "topsecret", "ip-10-0-0-5"} {
		if strings.Contains(out, leak) {
			t.Fatalf("SafeErrorBody leaked proxy metadata %q: %q", leak, out)
		}
	}
	if !strings.Contains(out, "kind=html") {
		t.Errorf("SafeErrorBody should classify a proxy page as html: %q", out)
	}
}

// TestSafeErrorBody_KindDetection covers the non-HTML branches.
func TestSafeErrorBody_KindDetection(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"xml", `<?xml version="1.0"?><error>nope</error>`, "kind=xml"},
		{"text", "upstream connect error or disconnect/reset before headers", "kind=text"},
		{"array", "[1,2,3]", ""}, // JSON array is preserved verbatim
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := SafeErrorBody([]byte(tc.body))
			if tc.want == "" {
				if out != tc.body {
					t.Errorf("JSON-ish body should be preserved; got %q", out)
				}
				return
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("SafeErrorBody(%q) = %q; want substring %q", tc.body, out, tc.want)
			}
		})
	}
}

// TestSafeErrorBody_PreservesJSONEnvelope verifies the provider's own
// structured JSON error is preserved so operators keep actionable detail.
func TestSafeErrorBody_PreservesJSONEnvelope(t *testing.T) {
	body := []byte(`{"error":"invalid_token","message":"token expired"}`)
	if got := SafeErrorBody(body); got != string(body) {
		t.Errorf("SafeErrorBody should preserve JSON error envelope; got %q", got)
	}
}

// TestSafeErrorBody_Empty verifies the empty-body sentinel.
func TestSafeErrorBody_Empty(t *testing.T) {
	if got := SafeErrorBody(nil); got != "(empty)" {
		t.Errorf("SafeErrorBody(nil) = %q; want (empty)", got)
	}
}

// TestSafeErrorBody_TruncatesJSONAtRuneBoundary verifies an oversized
// JSON body is capped on a valid UTF-8 rune boundary (downstream log
// pipelines reject invalid UTF-8).
func TestSafeErrorBody_TruncatesJSONAtRuneBoundary(t *testing.T) {
	const ellipsis = "\u2026" // 0xE2 0x80 0xA6
	prefix := "{" + strings.Repeat(" ", errorBodyJSONCap-2)
	body := []byte(prefix + ellipsis + strings.Repeat(ellipsis, 100))
	if !utf8.Valid(body) {
		t.Fatalf("test fixture is not valid UTF-8")
	}
	if utf8.RuneStart(body[errorBodyJSONCap]) {
		t.Fatalf("fixture does not exercise the boundary case")
	}
	out := SafeErrorBody(body)
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

// TestTruncateAtRune_Boundaries pins the precondition guards: max beyond
// len, max == len, max == 0, and nil/empty input must never index past
// the slice end (an earlier per-connector copy panicked at
// max == len(body)).
func TestTruncateAtRune_Boundaries(t *testing.T) {
	body := []byte("hello\u2026world") // ASCII + multi-byte rune
	if got := truncateAtRune(body, len(body)); got != string(body) {
		t.Errorf("truncateAtRune(body, len) = %q; want full body", got)
	}
	if got := truncateAtRune(body, len(body)+10); got != string(body) {
		t.Errorf("truncateAtRune past end = %q; want full body", got)
	}
	if got := truncateAtRune(body, 0); got != "" {
		t.Errorf("truncateAtRune(body, 0) = %q; want empty", got)
	}
	if got := truncateAtRune(nil, 8); got != "" {
		t.Errorf("truncateAtRune(nil, 8) = %q; want empty", got)
	}
	if got := truncateAtRune([]byte{}, 0); got != "" {
		t.Errorf("truncateAtRune(empty, 0) = %q; want empty", got)
	}
}

// TestBodyKind classifies proxy/provider payloads. HTML fragments (not
// just full <!doctype> documents) must classify as html, and
// whitespace-only bodies as empty, so the kind/length hint operators
// read is accurate.
func TestBodyKind(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"full-doctype", "<!DOCTYPE html><html></html>", "html"},
		{"html-fragment-div", "<div>maintenance in progress</div>", "html"},
		{"html-fragment-p", "<p>503 Service Unavailable</p>", "html"},
		{"html-fragment-h1", "<h1>Error</h1>", "html"},
		{"xml-declaration", `<?xml version="1.0"?><response/>`, "xml"},
		{"json-obj", `{"key":"value"}`, "json"},
		{"json-arr", `[1,2,3]`, "json"},
		{"plaintext", "internal server error", "text"},
		{"empty", "", "empty"},
		{"whitespace-only", "   \n\t  ", "empty"},
		{"leading-whitespace-html", "  \n<div>x</div>", "html"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := BodyKind([]byte(tc.body)); got != tc.want {
				t.Errorf("BodyKind(%q) = %q; want %q", tc.body, got, tc.want)
			}
		})
	}
}
