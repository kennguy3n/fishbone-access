package access

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SCIMResourceType enumerates the SCIM v2.0 resource kinds the
// generic provisioner client knows how to push. The base SCIM spec
// (RFC 7643) defines /Users and /Groups; downstream providers may
// add custom resource types but the generic client deliberately
// limits itself to the two RFC-mandated kinds.
type SCIMResourceType string

const (
	// SCIMResourceUser is the SCIM /Users endpoint.
	SCIMResourceUser SCIMResourceType = "Users"
	// SCIMResourceGroup is the SCIM /Groups endpoint.
	SCIMResourceGroup SCIMResourceType = "Groups"
)

// DefaultSCIMTimeout is the per-request timeout used when the
// connector config leaves base_url_timeout unset. Tuned slightly
// larger than the typical SaaS SCIM endpoint p99 (≈3s) so transient
// slowness doesn't churn the JML retry loop.
const DefaultSCIMTimeout = 10 * time.Second

// scimProvisionerConfigKey is the canonical config key for the
// SCIM v2.0 base URL. Exposed as a string so connector docs can
// reference it directly.
const scimProvisionerConfigKey = "scim_base_url"

// scimProvisionerSecretKey is the canonical secret key for the
// SCIM v2.0 bearer token (or any literal Authorization header
// value). gosec G101 false positive: this is the name of a key,
// not a credential value.
const scimProvisionerSecretKey = "scim_auth_header" // #nosec G101

// scimProvisionerTimeoutKey is the optional config key for the
// per-request SCIM timeout. The value MUST be a Go time.Duration
// string (e.g. "5s", "1m30s").
const scimProvisionerTimeoutKey = "scim_timeout"

// SCIMClient is the generic SCIM v2.0 client connectors compose to
// satisfy the SCIMProvisioner optional interface. It implements the
// SCIMProvisioner interface from optional_interfaces.go directly —
// connectors with a SCIM v2.0 backend can embed *SCIMClient and
// inherit the three method signatures.
//
// The client owns no per-request state; a single instance can be
// shared across goroutines and across connectors.
type SCIMClient struct {
	// httpClient is overridable so tests can swap in an
	// httptest.Server's Client(). Defaults to http.DefaultClient
	// in NewSCIMClient.
	httpClient *http.Client
}

// NewSCIMClient returns a client backed by http.DefaultClient. Tests
// override the http client via WithHTTPClient.
func NewSCIMClient() *SCIMClient {
	return &SCIMClient{httpClient: http.DefaultClient}
}

// WithHTTPClient replaces the underlying *http.Client. Returns the
// client so callers can chain. Intended for tests + production
// deployments that need a custom transport (e.g. mTLS, custom
// timeouts).
func (c *SCIMClient) WithHTTPClient(h *http.Client) *SCIMClient {
	if h != nil {
		c.httpClient = h
	}
	return c
}

// Sentinel errors returned by SCIMClient. Wrapped with fmt.Errorf so
// callers can errors.Is them without depending on message formats.
var (
	// ErrSCIMRemoteConflict signals the SCIM endpoint returned 409
	// Conflict — the resource already exists upstream. JML callers
	// MAY treat this as a successful no-op idempotent push (per
	// docs/architecture.md §8 connectors must be idempotent on
	// (UserExternalID, ResourceExternalID)).
	ErrSCIMRemoteConflict = errors.New("scim: remote returned 409 Conflict")

	// ErrSCIMRemoteNotFound signals the SCIM endpoint returned 404
	// Not Found. For DeleteSCIMResource this is treated as a
	// successful no-op idempotent delete; for Push this is a
	// configuration bug and surfaces to the operator.
	ErrSCIMRemoteNotFound = errors.New("scim: remote returned 404 Not Found")

	// ErrSCIMRemoteUnauthorized signals 401 / 403 — the auth
	// header is invalid or the token lacks SCIM scopes. The
	// connector layer should surface this as a validation error
	// during connector verify-permissions.
	ErrSCIMRemoteUnauthorized = errors.New("scim: remote returned 401/403 Unauthorized")

	// ErrSCIMRemoteServer signals a 5xx from the SCIM endpoint;
	// callers retry with exponential backoff.
	ErrSCIMRemoteServer = errors.New("scim: remote returned 5xx")

	// ErrSCIMConfigInvalid signals the config blob is missing
	// scim_base_url or has a malformed URL. Surfaces during
	// connector validation.
	ErrSCIMConfigInvalid = errors.New("scim: config invalid")
)

// PushSCIMUser POSTs the supplied SCIMUser to {scim_base_url}/Users.
// 409 Conflict surfaces as ErrSCIMRemoteConflict; callers MAY treat
// this as success because the SCIM contract requires idempotency on
// the (externalId, userName) tuple.
func (c *SCIMClient) PushSCIMUser(ctx context.Context, config, secrets map[string]interface{}, user SCIMUser) error {
	rcfg, err := readSCIMConfig(config, secrets)
	if err != nil {
		return err
	}
	body := scimUserPayload{
		Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		ExternalID:  user.ExternalID,
		UserName:    user.UserName,
		DisplayName: user.DisplayName,
		Active:      user.Active,
	}
	if user.Email != "" {
		body.Emails = []scimEmail{{Value: user.Email, Primary: true}}
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("scim: marshal user: %w", err)
	}
	if _, err := c.do(ctx, rcfg, http.MethodPost, string(SCIMResourceUser), payload); err != nil {
		return err
	}
	return nil
}

// PushSCIMGroup POSTs the supplied SCIMGroup to {scim_base_url}/Groups.
func (c *SCIMClient) PushSCIMGroup(ctx context.Context, config, secrets map[string]interface{}, group SCIMGroup) error {
	rcfg, err := readSCIMConfig(config, secrets)
	if err != nil {
		return err
	}
	members := make([]scimGroupMember, 0, len(group.MemberIDs))
	for _, id := range group.MemberIDs {
		members = append(members, scimGroupMember{Value: id})
	}
	body := scimGroupPayload{
		Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		ExternalID:  group.ExternalID,
		DisplayName: group.DisplayName,
		Members:     members,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("scim: marshal group: %w", err)
	}
	if _, err := c.do(ctx, rcfg, http.MethodPost, string(SCIMResourceGroup), payload); err != nil {
		return err
	}
	return nil
}

// DeleteSCIMResource DELETEs {scim_base_url}/{resourceType}/{externalID}.
// 404 from the remote is treated as success (idempotent delete);
// every other non-2xx surfaces as the matching sentinel error.
//
// resourceType MUST be "Users" or "Groups" (case-sensitive, per
// RFC 7644 §3.4.1) — the SCIM spec defines no other resources.
func (c *SCIMClient) DeleteSCIMResource(ctx context.Context, config, secrets map[string]interface{}, resourceType, externalID string) error {
	rcfg, err := readSCIMConfig(config, secrets)
	if err != nil {
		return err
	}
	if externalID == "" {
		return fmt.Errorf("%w: external_id is required for DELETE", ErrSCIMConfigInvalid)
	}
	rt := SCIMResourceType(resourceType)
	if rt != SCIMResourceUser && rt != SCIMResourceGroup {
		return fmt.Errorf("%w: unknown resource type %q", ErrSCIMConfigInvalid, resourceType)
	}
	path := string(rt) + "/" + url.PathEscape(externalID)
	_, err = c.do(ctx, rcfg, http.MethodDelete, path, nil)
	if errors.Is(err, ErrSCIMRemoteNotFound) {
		// SCIM DELETE is idempotent — a 404 means the resource is
		// already gone, which is a successful end state from the
		// caller's perspective.
		return nil
	}
	return err
}

// resolvedSCIMConfig is the parsed view of the (config, secrets)
// maps the client receives. Constructed once per request by
// readSCIMConfig.
type resolvedSCIMConfig struct {
	BaseURL    string
	AuthHeader string
	Timeout    time.Duration
}

// readSCIMConfig parses the (config, secrets) maps into a
// resolvedSCIMConfig and validates required fields. Returns
// ErrSCIMConfigInvalid wrapping the specific reason when validation
// fails so callers can errors.Is against the sentinel.
func readSCIMConfig(config, secrets map[string]interface{}) (resolvedSCIMConfig, error) {
	out := resolvedSCIMConfig{Timeout: DefaultSCIMTimeout}

	rawURL, ok := config[scimProvisionerConfigKey].(string)
	if !ok || strings.TrimSpace(rawURL) == "" {
		return out, fmt.Errorf("%w: %s is required", ErrSCIMConfigInvalid, scimProvisionerConfigKey)
	}
	// url.Parse alone is far too permissive — it accepts bare strings like
	// "not-a-url" as a relative-path URL and almost never errors. A SCIM base
	// URL must be an absolute http(s) endpoint, so require a host and an
	// http/https scheme here rather than letting a malformed value surface as a
	// confusing transport error on the first SCIM call.
	u, err := url.Parse(rawURL)
	if err != nil {
		return out, fmt.Errorf("%w: %s unparseable: %v", ErrSCIMConfigInvalid, scimProvisionerConfigKey, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return out, fmt.Errorf("%w: %s must be an http(s) URL (got scheme %q)", ErrSCIMConfigInvalid, scimProvisionerConfigKey, u.Scheme)
	}
	if u.Host == "" {
		return out, fmt.Errorf("%w: %s must include a host", ErrSCIMConfigInvalid, scimProvisionerConfigKey)
	}
	out.BaseURL = rawURL

	if header, ok := secrets[scimProvisionerSecretKey].(string); ok {
		out.AuthHeader = header
	}

	if rawTimeout, ok := config[scimProvisionerTimeoutKey].(string); ok && rawTimeout != "" {
		d, err := time.ParseDuration(rawTimeout)
		if err != nil {
			return out, fmt.Errorf("%w: %s unparseable: %v", ErrSCIMConfigInvalid, scimProvisionerTimeoutKey, err)
		}
		// A zero or negative timeout would make context.WithTimeout produce an
		// already-expired context, so every SCIM request would fail with
		// "context deadline exceeded" instead of doing real work. Reject it at
		// config time with an actionable error rather than failing silently.
		if d <= 0 {
			return out, fmt.Errorf("%w: %s must be positive (got %v)", ErrSCIMConfigInvalid, scimProvisionerTimeoutKey, d)
		}
		out.Timeout = d
	}

	return out, nil
}

// do issues the HTTP request, applies the auth header, dispatches
// status-code → sentinel mapping, and returns the response body
// for callers that want to parse it. Empty payload is allowed for
// DELETE.
func (c *SCIMClient) do(ctx context.Context, cfg resolvedSCIMConfig, method, path string, payload []byte) ([]byte, error) {
	rctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	endpoint, err := joinSCIMURL(cfg.BaseURL, path)
	if err != nil {
		return nil, err
	}
	var bodyReader io.Reader
	if len(payload) > 0 {
		bodyReader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(rctx, method, endpoint, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("scim: build %s %s: %w", method, endpoint, err)
	}
	req.Header.Set("Accept", "application/scim+json")
	if len(payload) > 0 {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	if cfg.AuthHeader != "" {
		req.Header.Set("Authorization", cfg.AuthHeader)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("scim: %s %s: %w", method, endpoint, err)
	}
	defer resp.Body.Close()
	respBody, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		// Surface the read failure rather than silently treating
		// it as an empty body — callers MUST see that the SCIM
		// envelope they expected may be incomplete so they can
		// retry instead of mis-interpreting a partial 2xx.
		return respBody, fmt.Errorf("scim: read %s %s body: %w", method, endpoint, readErr)
	}

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return respBody, nil
	case resp.StatusCode == http.StatusConflict:
		return respBody, fmt.Errorf("%w: %s", ErrSCIMRemoteConflict, truncate(string(respBody), 256))
	case resp.StatusCode == http.StatusNotFound:
		return respBody, fmt.Errorf("%w: %s %s", ErrSCIMRemoteNotFound, method, endpoint)
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return respBody, fmt.Errorf("%w: %d", ErrSCIMRemoteUnauthorized, resp.StatusCode)
	case resp.StatusCode >= 500:
		return respBody, fmt.Errorf("%w: %d", ErrSCIMRemoteServer, resp.StatusCode)
	default:
		return respBody, fmt.Errorf("scim: %s %s returned %d: %s", method, endpoint, resp.StatusCode, truncate(string(respBody), 256))
	}
}

// joinSCIMURL appends path to base, handling missing/duplicate
// trailing slashes. Returns the absolute URL string.
//
// The path argument is the caller-controlled, already-escaped form
// (e.g. "Users", "Groups/abc%40example.com"). joinSCIMURL is
// responsible for getting that pre-escaped string into both
// u.RawPath (verbatim) and u.Path (decoded), because Go's url.URL
// requires the two to be a consistent encoding pair — otherwise
// url.URL.EscapedPath observes the mismatch and silently
// re-encodes u.Path, double-encoding any percent sequence the
// caller supplied (turning "%40" into "%2540") and dropping
// pre-encoding the caller meant to preserve.
//
// Two scenarios make this matter in practice:
//
//  1. Base URL has percent-encoded segments (GitLab nested-group
//     path "my-org%2Fmy-subgroup"). url.Parse sets u.RawPath; we
//     must extend it in lockstep with u.Path or the "%2F" gets
//     re-encoded into "%252F" and the SCIM 404s.
//
//  2. DeleteSCIMResource appends an already-escaped externalID
//     (e.g. "Users/" + url.PathEscape("user@example.com") =
//     "Users/user%40example.com"). If we copied that raw form
//     verbatim into u.Path it would double-encode for the same
//     reason. We decode the appended segment for u.Path and keep
//     the raw form for u.RawPath.
func joinSCIMURL(base, path string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrSCIMConfigInvalid, err)
	}
	appendedRaw := "/" + strings.TrimLeft(path, "/")
	appendedDecoded, err := url.PathUnescape(appendedRaw)
	if err != nil {
		return "", fmt.Errorf("%w: invalid percent-encoding in path %q: %v", ErrSCIMConfigInvalid, path, err)
	}
	// When url.Parse encountered no percent-encoding in base, u.RawPath
	// is empty and u.Path doubles as the raw form. Promote it so we
	// can faithfully build a RawPath that contains the caller's
	// pre-encoding.
	baseRaw := u.RawPath
	if baseRaw == "" {
		baseRaw = u.Path
	}
	u.Path = strings.TrimRight(u.Path, "/") + appendedDecoded
	u.RawPath = strings.TrimRight(baseRaw, "/") + appendedRaw
	// If RawPath collapses to Path (no escaping anywhere in the
	// final URL) drop it so url.URL.String() emits the canonical
	// shortest form. This keeps the happy path output stable.
	if u.RawPath == u.Path {
		u.RawPath = ""
	}
	return u.String(), nil
}

// truncate caps s at n runes. Used for error messages so a chatty
// SCIM provider does not blow up the audit log. Counts runes (not
// bytes) so a multi-byte UTF-8 sequence is never sliced mid-rune
// and the resulting string is always valid UTF-8 even on hostile /
// non-ASCII payloads.
func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "\u2026"
}

// scimUserPayload is the wire shape PushSCIMUser sends. The struct
// is package-private; callers see only the SCIMUser DTO.
type scimUserPayload struct {
	Schemas     []string    `json:"schemas"`
	ExternalID  string      `json:"externalId,omitempty"`
	UserName    string      `json:"userName"`
	DisplayName string      `json:"displayName,omitempty"`
	Active      bool        `json:"active"`
	Emails      []scimEmail `json:"emails,omitempty"`
}

// scimEmail mirrors the SCIM Email multi-valued attribute.
type scimEmail struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
}

// scimGroupPayload is the wire shape PushSCIMGroup sends.
type scimGroupPayload struct {
	Schemas     []string          `json:"schemas"`
	ExternalID  string            `json:"externalId,omitempty"`
	DisplayName string            `json:"displayName"`
	Members     []scimGroupMember `json:"members,omitempty"`
}

// scimGroupMember mirrors one entry in the SCIM Group.members list.
type scimGroupMember struct {
	Value string `json:"value"`
}

// Verify SCIMClient satisfies the SCIMProvisioner contract from
// optional_interfaces.go at build time. The unused declaration is
// the canonical Go pattern for compile-time interface assertions.
var _ SCIMProvisioner = (*SCIMClient)(nil)
