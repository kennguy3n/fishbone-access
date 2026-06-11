package httputil

import (
	"fmt"
	"io"
)

// DefaultMaxBodyBytes is the process-side ceiling applied to a single connector
// response read when the caller does not specify one. It is deliberately large
// (64 MiB) so that legitimate audit windows and directory pages — which the
// connectors page through rather than return in one shot — are never rejected,
// while still bounding worst-case memory if an upstream misbehaves or is
// compromised. It is the defense-in-depth backstop that replaces the old
// per-connector 1 MiB caps, which were removed because they SILENTLY TRUNCATED
// valid responses at a byte boundary (dropping audit events and corrupting
// JSON). The distinction is the whole point: this limit ERRORS rather than
// truncates, so a body that exceeds it surfaces as a loud failure the caller
// can retry/alert on instead of a quiet data-integrity defect.
const DefaultMaxBodyBytes int64 = 64 << 20

// ReadAllLimited reads r fully but fails — rather than silently truncating — if
// it would exceed max bytes. A max <= 0 applies DefaultMaxBodyBytes.
//
// It reads up to max+1 bytes so that a body of exactly max is accepted while
// anything larger is detected and reported as an error. Callers retain
// ownership of closing the underlying body (these readers already defer Close).
func ReadAllLimited(r io.Reader, max int64) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("httputil: nil reader")
	}
	if max <= 0 {
		max = DefaultMaxBodyBytes
	}
	body, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("httputil: response body exceeds %d-byte limit", max)
	}
	return body, nil
}
