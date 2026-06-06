package ga4

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// advanced-capability mapping for Google Analytics 4 Admin API
// /v1beta/accounts/{account}/userLinks.
//
// GA4 identifies user links via the auto-generated resource name
// `accounts/{account}/userLinks/{userLinkId}` and exposes no per-email
// lookup endpoint, so the connector canonicalises AccessGrant.UserExternalID
// on the user's email address — the same value that the
// `accounts.userLinks.create` payload accepts as `emailAddress` and that
// SyncIdentities surfaces as Identity.ExternalID.
//
// When the caller already has the full resource name (e.g. cached from
// SyncIdentities.RawData["name"] or from a prior ProvisionAccess result)
// it can pass it verbatim as grant.UserExternalID — findUserLinkByExternalID
// detects the resource-name shape and issues a direct
// `GET /v1beta/{name=accounts/*/userLinks/*}` instead of paginating the
// /userLinks list. The slow path (paginate + filter by emailAddress) is
// the fallback for plain-email callers, since GA4 has no per-email lookup.
//
//   - ProvisionAccess  -> POST   /v1beta/accounts/{account}/userLinks
//   - RevokeAccess     -> resolve (fast: GET name; slow: list+filter),
//                         skip if role not present, else DELETE /v1beta/{name}
//   - ListEntitlements -> same resolve, then expose directRoles from the match
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2:
// repeated Provision returns nil on ALREADY_EXISTS, repeated Revoke returns
// nil when the userLink is absent OR when its directRoles already exclude
// the requested grant.ResourceExternalID.

// errGA4UserLinkNotFound is returned by findUserLinkByExternalID when the
// list / GET resolution finishes without locating a matching userLink.
// Callers (RevokeAccess, ListEntitlements) translate it into the idempotent
// no-op / empty-result they need, while other transport / decode errors
// propagate as-is so the caller can distinguish "absent" from "unknown".
var errGA4UserLinkNotFound = errors.New("ga4: userLink not found")

// isGA4UserLinkResourceName reports whether s matches the shape
// `accounts/{account}/userLinks/{userLinkId}` so the connector can take
// the direct-GET fast path instead of paginating /userLinks.
func isGA4UserLinkResourceName(s string) bool {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "accounts/") {
		return false
	}
	parts := strings.Split(s, "/")
	if len(parts) != 4 || parts[2] != "userLinks" {
		return false
	}
	return parts[1] != "" && parts[3] != ""
}

func ga4ValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("ga4: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("ga4: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *GA4AccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("ga4: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *GA4AccessConnector) userLinksURL(cfg Config) string {
	return c.baseURL() + c.userLinksPath(cfg)
}

// userLinkResourceURL builds the absolute URL for an individual userLink
// addressed by its full GA4 resource name (e.g.
// "accounts/123/userLinks/abc"). Per the GA4 Admin v1beta REST contract the
// slashes inside `{name=accounts/*/userLinks/*}` are part of the path and
// must NOT be percent-encoded.
func (c *GA4AccessConnector) userLinkResourceURL(name string) string {
	return c.baseURL() + "/v1beta/" + strings.TrimSpace(name)
}

func (c *GA4AccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	var rdr io.Reader
	if len(body) > 0 {
		rdr = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

// findUserLinkByExternalID resolves a GA4 admin grant's UserExternalID to
// the canonical resource name plus current directRoles, taking either of
// two paths depending on the input shape:
//
//   - Fast path: when userExternalID matches `accounts/*/userLinks/*` the
//     connector issues a single GET /v1beta/{name} and returns the entry
//     verbatim. A 404 → errGA4UserLinkNotFound; other non-2xx → transport
//     / decode error.
//   - Slow path: otherwise the connector paginates /userLinks and matches
//     on emailAddress case-insensitively. The slow path is O(N) in the
//     account's userLink count because GA4's v1beta surface exposes no
//     per-email lookup; callers that hold the resource name from a prior
//     SyncIdentities (Identity.RawData["name"]) or ProvisionAccess result
//     should pass it through to take the fast path.
//
// Both paths return errGA4UserLinkNotFound when no match is located. This
// sentinel disambiguates "absent" from other transport / decode failures
// so RevokeAccess can treat repeated revokes as idempotent and
// ListEntitlements can return an empty slice while still surfacing genuine
// API errors.
func (c *GA4AccessConnector) findUserLinkByExternalID(
	ctx context.Context, secrets Secrets, cfg Config, userExternalID string,
) (string, []string, error) {
	want := strings.TrimSpace(userExternalID)
	if want == "" {
		return "", nil, errors.New("ga4: user external id is required")
	}
	if isGA4UserLinkResourceName(want) {
		return c.getUserLinkByName(ctx, secrets, want)
	}
	base := c.baseURL()
	path := c.userLinksPath(cfg)
	token := ""
	for {
		q := url.Values{"pageSize": []string{fmt.Sprintf("%d", pageSize)}}
		if token != "" {
			q.Set("pageToken", token)
		}
		fullURL := base + path + "?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return "", nil, err
		}
		body, err := c.do(req)
		if err != nil {
			return "", nil, err
		}
		var resp ga4ListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return "", nil, fmt.Errorf("ga4: decode userLinks: %w", err)
		}
		for _, u := range resp.UserLinks {
			email := strings.TrimSpace(u.EmailAddress)
			name := strings.TrimSpace(u.Name)
			if strings.EqualFold(email, want) || name == want {
				return name, u.DirectRoles, nil
			}
		}
		if strings.TrimSpace(resp.NextPageToken) == "" {
			return "", nil, errGA4UserLinkNotFound
		}
		token = resp.NextPageToken
	}
}

// getUserLinkByName implements the resource-name fast path: it issues a
// single GET /v1beta/{name=accounts/*/userLinks/*} and parses the response
// into (name, directRoles). A 404 surfaces as errGA4UserLinkNotFound; other
// non-2xx is returned as a transport error so the caller can distinguish
// "absent" from "unknown".
func (c *GA4AccessConnector) getUserLinkByName(
	ctx context.Context, secrets Secrets, name string,
) (string, []string, error) {
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, c.userLinkResourceURL(name), nil)
	if err != nil {
		return "", nil, err
	}
	status, body, err := c.doRaw(req)
	if err != nil {
		return "", nil, err
	}
	switch {
	case status == http.StatusNotFound:
		return "", nil, errGA4UserLinkNotFound
	case status < 200 || status >= 300:
		return "", nil, fmt.Errorf("ga4: get userLink %s status %d: %s", name, status, string(body))
	}
	var link ga4UserLink
	if err := json.Unmarshal(body, &link); err != nil {
		return "", nil, fmt.Errorf("ga4: decode userLink: %w", err)
	}
	got := strings.TrimSpace(link.Name)
	if got == "" {
		got = name
	}
	return got, link.DirectRoles, nil
}

func (c *GA4AccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := ga4ValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"emailAddress": strings.TrimSpace(grant.UserExternalID),
		"directRoles":  []string{strings.TrimSpace(grant.ResourceExternalID)},
	})
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, c.userLinksURL(cfg), payload)
	if err != nil {
		return err
	}
	status, body, err := c.doRaw(req)
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case access.IsIdempotentProvisionStatus(status, body):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("ga4: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("ga4: provision status %d: %s", status, string(body))
	}
}

func (c *GA4AccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := ga4ValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	name, roles, err := c.findUserLinkByExternalID(ctx, secrets, cfg, grant.UserExternalID)
	if err != nil {
		if errors.Is(err, errGA4UserLinkNotFound) {
			// Already absent — idempotent revoke per docs/architecture.md §2.
			return nil
		}
		return err
	}
	// Use grant.ResourceExternalID as a presence guard: if the userLink
	// exists but does NOT currently carry the requested role, the revoke is
	// a semantic no-op (someone already removed it). GA4's v1beta DELETE
	// drops the entire userLink (and therefore every directRole on it), so
	// proceeding regardless would clobber unrelated grants for the same
	// user. Repeated revokes are idempotent through this branch as well.
	wantRole := strings.TrimSpace(grant.ResourceExternalID)
	if !containsRole(roles, wantRole) {
		return nil
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete, c.userLinkResourceURL(name), nil)
	if err != nil {
		return err
	}
	status, body, err := c.doRaw(req)
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case access.IsIdempotentRevokeStatus(status, body):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("ga4: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("ga4: revoke status %d: %s", status, string(body))
	}
}

// containsRole reports whether want appears in roles after trimming
// surrounding whitespace on each side. Used as the revoke presence guard
// so that revoking a role the userLink does not currently hold becomes an
// idempotent no-op (rather than wiping unrelated directRoles on the same
// userLink via DELETE).
func containsRole(roles []string, want string) bool {
	w := strings.TrimSpace(want)
	if w == "" {
		return false
	}
	for _, r := range roles {
		if strings.TrimSpace(r) == w {
			return true
		}
	}
	return false
}

func (c *GA4AccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("ga4: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	_, roles, err := c.findUserLinkByExternalID(ctx, secrets, cfg, user)
	if err != nil {
		if errors.Is(err, errGA4UserLinkNotFound) {
			return []access.Entitlement{}, nil
		}
		return nil, err
	}
	out := make([]access.Entitlement, 0, len(roles))
	for _, role := range roles {
		role = strings.TrimSpace(role)
		if role == "" {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: role,
			Role:               role,
			Source:             "direct",
		})
	}
	return out, nil
}
