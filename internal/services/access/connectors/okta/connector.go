// Package okta implements the access.AccessConnector contract for Okta.
//
// Capabilities:
//
//   - Validate (pure-local), Connect, VerifyPermissions
//   - CountIdentities, SyncIdentities (paginated /api/v1/users with Link header)
//   - SyncIdentitiesDelta (System Log polling; expired token → ErrDeltaTokenExpired)
//   - GetSSOMetadata (Okta OIDC discovery URL)
//   - GetCredentialsMetadata
//   - ProvisionAccess / RevokeAccess / ListEntitlements: real
//     implementations against /api/v1/apps/{appId}/users/{userId} and
//     /api/v1/users/{userId}/appLinks.
package okta

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/access/httputil"
)

// ErrNotImplemented is retained for any future capability that is not yet
// implemented; ProvisionAccess / RevokeAccess / ListEntitlements no longer
// return it now that the advanced capabilities are implemented.
var ErrNotImplemented = fmt.Errorf("okta: capability not supported by this connector: %w", access.ErrCapabilityNotSupported)

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// OktaAccessConnector implements access.AccessConnector and
// access.IdentityDeltaSyncer.
type OktaAccessConnector struct {
	// httpClient is the test-only injection point used by
	// connector_test.go to point requests at an httptest.Server.
	// Production code paths use sharedRetryClient instead so
	// every connector gets the 429 / 5xx retry-with-jitter
	// policy from internal/services/access/httputil.
	httpClient  func() httpDoer
	urlOverride string // optional base URL override (e.g. http://127.0.0.1:port) for tests
}

// New returns a fresh connector instance.
func New() *OktaAccessConnector {
	return &OktaAccessConnector{}
}

// ---------- Validate / Connect / VerifyPermissions ----------

func (c *OktaAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return err
	}
	if err := cfg.validate(); err != nil {
		return err
	}
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return err
	}
	return s.validate()
}

func (c *OktaAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, cfg, secrets, http.MethodGet, "/api/v1/org", nil)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("okta: connect probe: %w", err)
	}
	return nil
}

// VerifyPermissions probes /api/v1/users?limit=1. If the API token has the
// required scope the call returns 200; anything else surfaces as a missing
// capability rather than an error.
func (c *OktaAccessConnector) VerifyPermissions(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	capabilities []string,
) ([]string, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, cap := range capabilities {
		switch cap {
		case "sync_identity":
			req, err := c.newRequest(ctx, cfg, secrets, http.MethodGet, "/api/v1/users?limit=1", nil)
			if err != nil {
				return nil, err
			}
			if _, err := c.do(req); err != nil {
				missing = append(missing, fmt.Sprintf("sync_identity (%v)", err))
			}
		default:
			missing = append(missing, fmt.Sprintf("%s (no probe defined)", cap))
		}
	}
	return missing, nil
}

// ---------- Identity sync ----------

// CountIdentities reads the X-Total-Count header if Okta returns it. Most
// Okta orgs do not, so the connector returns -1 to signal unknown.
func (c *OktaAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	req, err := c.newRequest(ctx, cfg, secrets, http.MethodGet, "/api/v1/users?limit=1", nil)
	if err != nil {
		return 0, err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return 0, fmt.Errorf("okta: count probe status %d: %s", resp.StatusCode, string(body))
	}
	if total := resp.Header.Get("X-Total-Count"); total != "" {
		if n, err := strconv.Atoi(total); err == nil {
			return n, nil
		}
	}
	return -1, nil
}

// SyncIdentities pages through /api/v1/users using the RFC-5988 Link header
// rel="next" pagination Okta uses.
func (c *OktaAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}

	// Resolve the start URL: full URL from checkpoint or the canonical
	// /api/v1/users path on the configured Okta domain.
	startURL := checkpoint
	if startURL == "" {
		startURL = c.absURL(cfg, "/api/v1/users?limit=200")
	}

	for next := startURL; next != ""; {
		if err := ctx.Err(); err != nil {
			return err
		}
		reqURL := next
		if c.urlOverride != "" {
			reqURL = c.rewriteForTest(reqURL)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "SSWS "+strings.TrimPrefix(secrets.APIToken, "SSWS "))
		req.Header.Set("Accept", "application/json")

		resp, err := c.doRaw(req)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			_ = resp.Body.Close()
			return fmt.Errorf("okta: users page status %d: %s", resp.StatusCode, string(body))
		}

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return err
		}

		var users []oktaUser
		if err := json.Unmarshal(body, &users); err != nil {
			return fmt.Errorf("okta: decode users: %w", err)
		}
		batch := mapOktaUsers(users)
		nextLink := parseNextLink(resp.Header.Get("Link"))
		if err := handler(batch, nextLink); err != nil {
			return err
		}
		next = nextLink
	}
	return nil
}

// SyncIdentitiesDelta polls Okta's /api/v1/logs system-log endpoint for
// USER_CREATED / USER_UPDATED / USER_DEACTIVATED events since the last
// deltaLink. An expired or rejected since token surfaces as
// access.ErrDeltaTokenExpired.
func (c *OktaAccessConnector) SyncIdentitiesDelta(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	deltaLink string,
	handler func(batch []*access.Identity, removedExternalIDs []string, nextLink string) error,
) (string, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return "", err
	}

	startURL := deltaLink
	if startURL == "" {
		// Default to "from now" on first run.
		since := time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339)
		startURL = c.absURL(cfg, "/api/v1/logs?since="+url.QueryEscape(since))
	}

	var finalDeltaLink string
	for next := startURL; next != ""; {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		reqURL := next
		if c.urlOverride != "" {
			reqURL = c.rewriteForTest(reqURL)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Authorization", "SSWS "+strings.TrimPrefix(secrets.APIToken, "SSWS "))
		req.Header.Set("Accept", "application/json")

		resp, err := c.doRaw(req)
		if err != nil {
			return "", err
		}

		switch resp.StatusCode {
		case http.StatusOK:
			// fallthrough below
		case http.StatusGone, http.StatusBadRequest:
			// Okta returns 400 with E0000031 when the since cursor is
			// out of retention; we treat both 410 and 400 as expired.
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			_ = resp.Body.Close()
			if isExpiredCursorBody(body) {
				return "", access.ErrDeltaTokenExpired
			}
			if resp.StatusCode == http.StatusGone {
				return "", access.ErrDeltaTokenExpired
			}
			return "", fmt.Errorf("okta: logs status %d: %s", resp.StatusCode, string(body))
		default:
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			_ = resp.Body.Close()
			return "", fmt.Errorf("okta: logs status %d: %s", resp.StatusCode, string(body))
		}

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return "", err
		}
		var events []oktaLogEvent
		if err := json.Unmarshal(body, &events); err != nil {
			return "", fmt.Errorf("okta: decode logs: %w", err)
		}
		batch, removed := mapOktaLogEvents(events)
		nextLink := parseNextLink(resp.Header.Get("Link"))
		if err := handler(batch, removed, nextLink); err != nil {
			return "", err
		}
		// On the last page, reuse the canonical request URL (next) as the
		// finalDeltaLink — never reqURL, which may have been rewritten to
		// the httptest host under urlOverride. In production the two are
		// identical, but persisting the canonical Okta-domain URL keeps the
		// stored delta cursor valid regardless of test rewriting.
		if nextLink == "" {
			finalDeltaLink = next
		}
		next = nextLink
	}
	return finalDeltaLink, nil
}

// ---------- advanced capabilities ----------

// ProvisionAccess assigns the user to the app. The grant.ResourceExternalID is
// the Okta application id; grant.Role is mapped onto the assignment's
// `profile` payload (the Okta API accepts an arbitrary key/value JSON object
// here — we send {"role": grant.Role} for the simplest case). 409 Conflict on
// assign is treated as idempotent success.
func (c *OktaAccessConnector) ProvisionAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if err := validateGrantPair(grant); err != nil {
		return err
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	profile := map[string]string{}
	if grant.Role != "" {
		profile["role"] = grant.Role
	}
	body, err := json.Marshal(oktaAppUserAssignment{
		ID:      grant.UserExternalID,
		Scope:   "USER",
		Profile: profile,
	})
	if err != nil {
		return fmt.Errorf("okta: marshal assignment: %w", err)
	}
	// Assign via POST /api/v1/apps/{appId}/users with the user id in the body
	// — this is Okta's documented "Assign User to Application for SSO &
	// Provisioning" endpoint and creates the assignment when none exists.
	// PUT /api/v1/apps/{appId}/users/{userId} is NOT an assignment verb: that
	// path only supports POST (update the profile of an *already assigned*
	// user) and DELETE (unassign), so a PUT first-provision would fail. The
	// request body shape (id/scope/profile) is identical, so only the verb and
	// path change.
	path := fmt.Sprintf("/api/v1/apps/%s/users",
		url.PathEscape(grant.ResourceExternalID),
	)
	req, err := c.newRequest(ctx, cfg, secrets, http.MethodPost, path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.doRaw(req)
	if err != nil {
		return fmt.Errorf("okta: provision request: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusConflict:
		return nil
	default:
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("okta: provision status %d: %s", resp.StatusCode, string(rb))
	}
}

// RevokeAccess deletes the user's app assignment. 404 is idempotent success.
func (c *OktaAccessConnector) RevokeAccess(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	grant access.AccessGrant,
) error {
	if err := validateGrantPair(grant); err != nil {
		return err
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/api/v1/apps/%s/users/%s",
		url.PathEscape(grant.ResourceExternalID),
		url.PathEscape(grant.UserExternalID),
	)
	req, err := c.newRequest(ctx, cfg, secrets, http.MethodDelete, path, nil)
	if err != nil {
		return err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return fmt.Errorf("okta: revoke request: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusNotFound:
		return nil
	default:
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("okta: revoke status %d: %s", resp.StatusCode, string(rb))
	}
}

// ListEntitlements pages through /api/v1/users/{userExternalID}/appLinks and
// maps each appLink to Entitlement{ResourceExternalID: appInstanceId, Role:
// label, Source: "direct"}. Pagination uses RFC-5988 Link headers.
func (c *OktaAccessConnector) ListEntitlements(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) ([]access.Entitlement, error) {
	if userExternalID == "" {
		return nil, errors.New("okta: user external id is required")
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}

	path := fmt.Sprintf("/api/v1/users/%s/appLinks", url.PathEscape(userExternalID))
	var out []access.Entitlement
	for {
		// Honor cancellation at the loop boundary so a cancelled context
		// returns immediately rather than after the next network round-trip,
		// matching SyncIdentities/SyncGroups/FetchAccessAuditLogs.
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req, err := c.newRequest(ctx, cfg, secrets, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		resp, err := c.doRaw(req)
		if err != nil {
			return nil, fmt.Errorf("okta: list appLinks: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			_ = resp.Body.Close()
			return nil, fmt.Errorf("okta: list appLinks status %d: %s", resp.StatusCode, string(rb))
		}
		body, err := io.ReadAll(resp.Body)
		next := parseNextLink(resp.Header.Get("Link"))
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		var links []oktaAppLink
		if err := json.Unmarshal(body, &links); err != nil {
			return nil, fmt.Errorf("okta: decode appLinks: %w", err)
		}
		for _, link := range links {
			out = append(out, access.Entitlement{
				ResourceExternalID: link.AppInstanceID,
				Role:               link.Label,
				Source:             "direct",
			})
		}
		if next == "" {
			return out, nil
		}
		// Reduce the absolute next-page URL from the Link header to its
		// path+query and let newRequest/absURL re-prepend the base. No
		// rewriteForTest is needed here (unlike SyncIdentities, which passes
		// the full URL straight to http.NewRequestWithContext): RequestURI
		// discards scheme+host anyway, so rewriting the host first was wasted
		// work that obscured intent.
		u, err := url.Parse(next)
		if err != nil {
			return nil, err
		}
		path = u.RequestURI()
	}
}

func validateGrantPair(grant access.AccessGrant) error {
	if grant.UserExternalID == "" {
		return errors.New("okta: grant.UserExternalID is required")
	}
	if grant.ResourceExternalID == "" {
		return errors.New("okta: grant.ResourceExternalID is required")
	}
	return nil
}

type oktaAppUserAssignment struct {
	ID      string            `json:"id"`
	Scope   string            `json:"scope"`
	Profile map[string]string `json:"profile,omitempty"`
}

type oktaAppLink struct {
	AppInstanceID string `json:"appInstanceId"`
	AppName       string `json:"appName"`
	Label         string `json:"label"`
}

// ---------- Metadata ----------

func (c *OktaAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	domain := cfg.normalisedDomain()
	return &access.SSOMetadata{
		Protocol:    "oidc",
		MetadataURL: fmt.Sprintf("https://%s/.well-known/openid-configuration", domain),
		EntityID:    fmt.Sprintf("https://%s", domain),
		SSOLoginURL: fmt.Sprintf("https://%s/oauth2/v1/authorize", domain),
	}, nil
}

func (c *OktaAccessConnector) GetCredentialsMetadata(_ context.Context, _, _ map[string]interface{}) (map[string]interface{}, error) {
	return map[string]interface{}{
		"provider": ProviderName,
		"note":     "API token expiry is not exposed by the Okta API; populate via renewal cron",
	}, nil
}

// ---------- Internal helpers ----------

func decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return Config{}, Secrets{}, err
	}
	if err := cfg.validate(); err != nil {
		return Config{}, Secrets{}, err
	}
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return Config{}, Secrets{}, err
	}
	if err := s.validate(); err != nil {
		return Config{}, Secrets{}, err
	}
	return cfg, s, nil
}

func (c *OktaAccessConnector) absURL(cfg Config, path string) string {
	if c.urlOverride != "" {
		return c.urlOverride + path
	}
	return "https://" + cfg.normalisedDomain() + path
}

// rewriteForTest replaces the absolute Okta URL in a Link-header next link
// with the test-server base URL, so paginated test fixtures still resolve.
func (c *OktaAccessConnector) rewriteForTest(rawURL string) string {
	if c.urlOverride == "" {
		return rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	override, err := url.Parse(c.urlOverride)
	if err != nil {
		return rawURL
	}
	u.Scheme = override.Scheme
	u.Host = override.Host
	return u.String()
}

func (c *OktaAccessConnector) newRequest(ctx context.Context, cfg Config, secrets Secrets, method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.absURL(cfg, path), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "SSWS "+strings.TrimPrefix(secrets.APIToken, "SSWS "))
	req.Header.Set("Accept", "application/json")
	return req, nil
}

func (c *OktaAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.doRaw(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("okta: %s status %d: %s", req.URL.Path, resp.StatusCode, string(body))
	}
	return io.ReadAll(resp.Body)
}

func (c *OktaAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	if c.httpClient != nil {
		// Test injection point. Tests build httptest.Server
		// responses to exercise the connector's parsing /
		// error-classification logic; they should NOT be
		// gated by the production retry policy.
		return c.httpClient().Do(req)
	}
	// Production path: route through the shared RetryClient
	// so Okta's 429 (E0000047 rate-limit) and CDN 502/503/504
	// hiccups are retried with Retry-After honoured. The
	// per-attempt timeout matches the previous hardcoded
	// 30s so connector latency observed by callers is
	// unchanged on the happy path.
	return sharedRetryClient.Do(req.Context(), req)
}

// sharedRetryClient is a package-level singleton that wraps the
// httputil.RetryClient defaults. Singleton (rather than per-call
// instantiation) so the underlying *http.Client connection pool
// is reused across requests — Okta enforces per-tenant connection
// limits, and a fresh *http.Client per call would defeat keep-alive
// and burn the tenant's quota.
var sharedRetryClient = httputil.NewRetryClient(30 * time.Second)

// linkNextRE matches the rel="next" entry in an RFC-5988 Link header.
var linkNextRE = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

func parseNextLink(linkHeader string) string {
	if linkHeader == "" {
		return ""
	}
	m := linkNextRE.FindStringSubmatch(linkHeader)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func isExpiredCursorBody(body []byte) bool {
	return strings.Contains(string(body), "E0000031") ||
		strings.Contains(string(body), "expired") ||
		strings.Contains(string(body), "out of retention")
}

func mapOktaUsers(users []oktaUser) []*access.Identity {
	out := make([]*access.Identity, 0, len(users))
	for _, u := range users {
		out = append(out, &access.Identity{
			ExternalID:  u.ID,
			Type:        access.IdentityTypeUser,
			DisplayName: strings.TrimSpace(u.Profile.FirstName + " " + u.Profile.LastName),
			Email:       firstNonEmpty(u.Profile.Email, u.Profile.Login),
			Status:      strings.ToLower(u.Status),
		})
	}
	return out
}

func mapOktaLogEvents(events []oktaLogEvent) ([]*access.Identity, []string) {
	identities := make([]*access.Identity, 0, len(events))
	var removed []string
	for _, e := range events {
		var userID, userEmail string
		for _, t := range e.Target {
			if strings.EqualFold(t.Type, "User") {
				userID = t.ID
				userEmail = t.AlternateID
				break
			}
		}
		if userID == "" {
			continue
		}
		switch e.EventType {
		case "user.lifecycle.delete.completed", "user.lifecycle.deactivate":
			removed = append(removed, userID)
		default:
			// A delta event signals the user changed; emit the status the
			// event implies so the record isn't misreported as active.
			// Suspend/lock keep the user as an identity (not removed) but
			// in a non-active state, using the same lowercased vocabulary
			// as the full sync (strings.ToLower(u.Status)). Anything else
			// (activate, unsuspend, unlock, profile update, ...) is active.
			status := "active"
			switch {
			case strings.HasPrefix(e.EventType, "user.lifecycle.suspend"):
				status = "suspended"
			case strings.HasPrefix(e.EventType, "user.account.lock"):
				status = "locked_out"
			}
			identities = append(identities, &access.Identity{
				ExternalID: userID,
				Type:       access.IdentityTypeUser,
				Email:      userEmail,
				Status:     status,
			})
		}
	}
	return identities, removed
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// ---------- Okta DTOs ----------

type oktaUser struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Profile struct {
		Login     string `json:"login"`
		Email     string `json:"email"`
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
	} `json:"profile"`
}

type oktaLogEvent struct {
	EventType string         `json:"eventType"`
	Published string         `json:"published"`
	Target    []oktaLogActor `json:"target"`
}

type oktaLogActor struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	AlternateID string `json:"alternateId"`
	DisplayName string `json:"displayName"`
}

// InitialDeltaCursor returns a /api/v1/logs URL with `since` set to
// "now" so the very next SyncIdentitiesDelta only consumes events
// emitted after the orchestrator finished its full sync. No network
// call.
func (c *OktaAccessConnector) InitialDeltaCursor(
	_ context.Context,
	configRaw, secretsRaw map[string]interface{},
) (string, error) {
	cfg, _, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return "", err
	}
	since := time.Now().UTC().Format(time.RFC3339)
	return c.absURL(cfg, "/api/v1/logs?since="+url.QueryEscape(since)), nil
}

// ---------- compile-time interface assertions ----------

var (
	_ access.AccessConnector     = (*OktaAccessConnector)(nil)
	_ access.IdentityDeltaSyncer = (*OktaAccessConnector)(nil)
)
