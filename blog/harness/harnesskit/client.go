// Package harnesskit holds the plumbing shared by the blog evidence harnesses
// (blog/harness/seed and blog/harness/capture): HS256 token minting compatible
// with the control plane's non-production dev validator, a thin HTTP client
// with idempotent-aware status handling, and the canonical definition of the
// six demo workspaces.
//
// Both harnesses drive the REAL control-plane API — nothing here hand-authors a
// payload. The seed harness mutates state through the same validation / RBAC /
// step-up-MFA / audit chain a console user hits; the capture harness GETs the
// resulting state back verbatim.
package harnesskit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// DefaultIssuer / DefaultAudience match cmd/ztna-api's dev-auth defaults
// (AUTH_JWT_ISSUER / AUTH_JWT_AUDIENCE). The minted token's iss/aud must equal
// what the server enforces or validation fails closed.
const (
	DefaultIssuer   = "fishbone-access-dev"
	DefaultAudience = "fishbone-access"
)

// StepUpHeader is the request header carrying a fresh step-up MFA assertion
// (the 6-digit TOTP code) for high-risk routes such as policy promote and
// evidence-pack export. It mirrors middleware.StepUpAssertionHeader.
const StepUpHeader = "X-MFA-Assertion"

// MintJWT builds an HS256 bearer token shaped like an iam-core access token, so
// the control plane's dev validator (internal/iamcore/devauth.go) extracts the
// same Claims a production JWKS token would yield. tenantID populates the
// tenant_id claim RequireTenant resolves to a workspace; mfa=true satisfies the
// RequireMFA gate on high-risk routes (step-up TOTP is supplied separately, per
// request, via the X-MFA-Assertion header).
func MintJWT(secret, issuer, audience, sub, tenantID string, roles []string, mfa bool, ttl time.Duration) string {
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	hdr := b64([]byte(`{"alg":"HS256","typ":"JWT"}`))
	now := time.Now().Unix()
	claims := map[string]any{
		"iss":       issuer,
		"aud":       audience,
		"sub":       sub,
		"tenant_id": tenantID,
		"roles":     roles,
		"mfa":       mfa,
		"iat":       now,
		"nbf":       now,
		"exp":       time.Now().Add(ttl).Unix(),
	}
	cb, _ := json.Marshal(claims)
	seg := hdr + "." + b64(cb)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(seg))
	return seg + "." + b64(mac.Sum(nil))
}

// Client is a minimal authenticated HTTP client for one workspace identity.
type Client struct {
	Base    string
	Token   string
	HTTP    *http.Client
	Verbose bool
}

// NewClient returns a Client with a bounded timeout.
func NewClient(base, token string, verbose bool) *Client {
	return &Client{
		Base:    strings.TrimRight(base, "/"),
		Token:   token,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
		Verbose: verbose,
	}
}

// Request issues one request and returns the status code and raw body. headers
// are applied last so a caller can add e.g. the step-up assertion. It never
// treats a non-2xx as a transport error — the status is returned for the caller
// to interpret (a 409 is success-as-idempotency for the seed).
func (c *Client) Request(method, path string, body any, headers map[string]string) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, fmt.Errorf("marshal body for %s %s: %w", method, path, err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, c.Base+path, rdr)
	if err != nil {
		return 0, nil, fmt.Errorf("build %s %s: %w", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("read body %s %s: %w", method, path, err)
	}
	return resp.StatusCode, raw, nil
}

// JSON issues a request, decodes a 2xx body into out (when non-nil), and
// reports ok. A 409 Conflict is the idempotency signal — the resource already
// exists in the desired state — and returns ok=false WITHOUT logging a failure,
// so a re-run is quiet and the summary's server-side counts remain ground
// truth. Any other non-2xx logs a FAIL line and returns ok=false.
func (c *Client) JSON(method, path string, body, out any) bool {
	return c.JSONHdr(method, path, body, out, nil)
}

// JSONHdr is JSON with caller-supplied headers (used to carry the step-up MFA
// assertion on high-risk routes such as policy promote).
func (c *Client) JSONHdr(method, path string, body, out any, headers map[string]string) bool {
	status, raw, err := c.Request(method, path, body, headers)
	if err != nil {
		Logf("ERR %s %s: %v", method, path, err)
		return false
	}
	if status >= 200 && status < 300 {
		if out != nil && len(raw) > 0 {
			if err := json.Unmarshal(raw, out); err != nil {
				Logf("ERR decode %s %s: %v", method, path, err)
				return false
			}
		}
		if c.Verbose {
			Logf("OK   %d %s %s", status, method, path)
		}
		return true
	}
	if status == http.StatusConflict {
		if c.Verbose {
			Logf("EXISTS %s %s", method, path)
		}
		return false
	}
	Logf("FAIL %d %s %s: %s", status, method, path, strings.TrimSpace(string(raw)))
	return false
}

// Logf writes a diagnostic line to stderr (stdout stays clean for any piped
// JSON).
func Logf(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...) }

// Fatalf logs and exits non-zero.
func Fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "fatal: "+format+"\n", args...)
	os.Exit(1)
}
