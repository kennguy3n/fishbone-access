package auth0

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// CheckSSOEnforcement implements access.SSOEnforcementChecker for
// Auth0. The probe lists every Auth0 connection (via
// /api/v2/connections) and inspects the strategy field; if every
// active connection uses an enterprise federation strategy (e.g.
// "samlp", "oidc", "okta", "google-apps", "adfs", "waad") and
// none use a password / social strategy, the tenant is considered
// SSO-only.
//
// Only `name` and `strategy` are decoded
// off each connection. The Auth0 API also surfaces an
// `enabled_clients` field, but it is a JSON array of client-ID
// strings — decoding it into anything narrower (e.g. *bool) makes
// json.Decoder.Decode raise UnmarshalTypeError on every real Auth0
// tenant, so the probe silently fails closed for everybody. We do
// not consult `enabled_clients` in this check, so it is simply
// omitted from the struct.
//
// Best-effort: a transport or authentication failure returns a
// non-nil err so callers map the connector to "unknown" rather
// than "not_enforced".
//
// The connections endpoint is paginated
// with a 100-record page size. The probe loops `?page=N&per_page=100`
// until the API returns a short page (fewer than the page size),
// so an Auth0 tenant with more than 100 connections cannot hide a
// password / social connection beyond page 0 and produce a false
// positive "SSO enforced" verdict.
func (c *Auth0AccessConnector) CheckSSOEnforcement(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (bool, string, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return false, "", err
	}
	token, err := c.fetchAccessToken(ctx, cfg, secrets)
	if err != nil {
		return false, "", fmt.Errorf("auth0: sso-enforcement: authenticate: %w", err)
	}

	const pageSize = 100
	// Hard cap on the number of pages we walk so a misbehaving
	// upstream (e.g. an API that always returns a full page)
	// cannot turn this probe into an unbounded loop. 1024 pages
	// at 100 records each is 102 400 connections — orders of
	// magnitude above any real-world Auth0 tenant.
	const maxPages = 1024
	var (
		openStrategies  []string
		enterpriseCount int
	)
	for page := 0; page < maxPages; page++ {
		path := fmt.Sprintf("/api/v2/connections?page=%d&per_page=%d", page, pageSize)
		req, err := c.newAuthedRequest(ctx, cfg, token, http.MethodGet, path, nil)
		if err != nil {
			return false, "", err
		}
		resp, err := c.doRaw(req)
		if err != nil {
			return false, "", fmt.Errorf("auth0: sso-enforcement probe page=%d: %w", page, err)
		}
		// Body must be closed before the next iteration's request
		// fires, so we drain + close inline rather than via defer.
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			_ = resp.Body.Close()
			return false, "", fmt.Errorf("auth0: sso-enforcement status %d page=%d: %s", resp.StatusCode, page, string(body))
		}
		var conns []struct {
			Name     string `json:"name"`
			Strategy string `json:"strategy"`
		}
		decodeErr := json.NewDecoder(resp.Body).Decode(&conns)
		_ = resp.Body.Close()
		if decodeErr != nil {
			return false, "", fmt.Errorf("auth0: decode connections page=%d: %w", page, decodeErr)
		}
		for _, conn := range conns {
			switch strings.ToLower(conn.Strategy) {
			case "auth0", "auth0-passwordless", "auth0-adldap",
				"google-oauth2", "facebook", "github",
				"linkedin", "twitter", "microsoft", "windowslive",
				"apple", "yahoo", "amazon", "dropbox", "vkontakte",
				"yandex", "salesforce", "fitbit", "evernote",
				"weibo", "renren", "baidu", "thirtysevensignals",
				"sms", "email":
				openStrategies = append(openStrategies, conn.Name+"/"+conn.Strategy)
			default:
				enterpriseCount++
			}
		}
		// A short page (or an empty page) means we just consumed
		// the tail of the connections list. The Auth0 API does
		// not return a "has_more" flag; the contract is "fewer
		// than per_page rows means you're done".
		if len(conns) < pageSize {
			break
		}
	}

	if len(openStrategies) > 0 {
		return false, fmt.Sprintf(
			"Auth0 tenant still allows password or social sign-in via %d connection(s): %s",
			len(openStrategies), strings.Join(openStrategies, ", "),
		), nil
	}
	if enterpriseCount == 0 {
		return false, "Auth0 tenant has no active enterprise connections — sign-on policy cannot be enforced", nil
	}
	return true, fmt.Sprintf(
		"Auth0 tenant has only enterprise federation connections active (%d)",
		enterpriseCount,
	), nil
}
