package httputil

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// SafeErrorBody scrubs an upstream HTTP error body before it is embedded
// in an error message. A reverse proxy or load balancer in front of the
// provider API can return an HTML/XML error page whose body may carry
// sensitive metadata (trace IDs, cookie names, internal hostnames).
// Echoing the raw body into an error string would leak that metadata
// into operator dashboards and logs. The provider's own JSON error
// envelope is preserved (capped and truncated on a UTF-8 rune boundary
// so downstream log pipelines never see invalid UTF-8), while any
// non-JSON payload is reduced to a kind/length hint.
//
// This is the shared implementation every connector calls; it replaces
// the per-connector formatErrorBody copies so a change to the scrubbing
// or kind-detection logic is made in exactly one place.
const errorBodyJSONCap = 4 << 10

func SafeErrorBody(body []byte) string {
	if len(body) == 0 {
		return "(empty)"
	}
	kind := BodyKind(body)
	if kind == "json" {
		if len(body) > errorBodyJSONCap {
			return truncateAtRune(body, errorBodyJSONCap) + " …(truncated)"
		}
		return string(body)
	}
	return fmt.Sprintf("(kind=%s, len=%d)", kind, len(body))
}

// truncateAtRune returns the longest prefix of body of length <= max
// that ends on a valid UTF-8 rune boundary, so a multi-byte rune split
// by the cap never yields an invalid-UTF-8 error surface. When
// max >= len(body) the whole body is returned without indexing past the
// slice end.
func truncateAtRune(body []byte, max int) string {
	if max >= len(body) {
		return string(body)
	}
	end := max
	for end > 0 && !utf8.RuneStart(body[end]) {
		end--
	}
	return string(body[:end])
}

// BodyKind returns a short hint about the upstream payload kind from its
// first non-whitespace bytes, so operators can route an incident without
// us echoing a possibly sensitive non-JSON body. Angle-bracketed
// payloads default to "html" because proxy error pages are
// overwhelmingly HTML fragments; an explicit <?xml prefix returns "xml".
// Only the first bodyKindPrefixBytes are inspected so a multi-MB proxy
// page is not re-scanned in full just to classify it. It is exported so
// callers that need only the classification (e.g. splunk's SSO check,
// which embeds a kind/length hint without echoing the body) share the
// same single implementation as SafeErrorBody.
const bodyKindPrefixBytes = 64

func BodyKind(body []byte) string {
	start := 0
	for start < len(body) {
		switch body[start] {
		case ' ', '\t', '\n', '\r', '\v', '\f':
			start++
			continue
		}
		break
	}
	if start >= len(body) {
		return "empty"
	}
	end := start + bodyKindPrefixBytes
	if end > len(body) {
		end = len(body)
	}
	prefix := strings.ToLower(string(body[start:end]))
	switch {
	case strings.HasPrefix(prefix, "<?xml"):
		return "xml"
	case strings.HasPrefix(prefix, "<"):
		return "html"
	case strings.HasPrefix(prefix, "{"),
		strings.HasPrefix(prefix, "["):
		return "json"
	default:
		return "text"
	}
}
