package jira

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// CheckSSOEnforcement implements access.SSOEnforcementChecker for
// Jira / Atlassian. The Atlassian admin API exposes per-organisation
// authentication policies at
// `GET /admin/v1/orgs/{orgID}/authentication-policies` (Atlassian
// Access). When at least one policy has `attributes.ssoOnly==true`
// applied to all users, the org enforces SSO and password sign-in is
// blocked for everyone in scope.
//
// Best-effort: transport / authorisation failures surface as a
// non-nil err so callers map them to "unknown" — never to "not
// enforced".
func (c *JiraAccessConnector) CheckSSOEnforcement(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (bool, string, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return false, "", err
	}
	orgID, _ := configRaw["org_id"].(string)
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		// org_id is the Atlassian *organization* identifier the admin API
		// keys on (/admin/v1/orgs/{orgID}/...). cloud_id is a distinct
		// per-site *product* identifier (/ex/jira/{cloudID}) and is not
		// interchangeable: substituting it here produces a misleading 404
		// from the admin gateway that masquerades as "SSO not enforced".
		// Require org_id explicitly, matching SyncIdentitiesDelta.
		return false, "", errors.New("jira: sso-enforcement: config.org_id is required (cloud_id is a per-site product id, not the Atlassian org id)")
	}
	endpoint := c.adminBaseURL() + "/admin/v1/orgs/" + url.PathEscape(orgID) + "/authentication-policies"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, endpoint)
	if err != nil {
		return false, "", err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return false, "", fmt.Errorf("jira: sso-enforcement probe: %w", err)
	}
	// The deferred drainAndClose consumes any bytes beyond what we read and
	// closes the body so net/http can return the connection to the keep-alive
	// pool, matching the write paths in connector.go / session_revoke.go.
	defer drainAndClose(resp)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return false, "", fmt.Errorf("jira: sso-enforcement status %d: %s", resp.StatusCode, string(body))
	}
	// Read the success body through io.LimitReader (1MiB cap) before
	// unmarshalling instead of json.NewDecoder(resp.Body) directly: a bare
	// decoder reads the whole top-level JSON value unbounded, so a misbehaving
	// admin gateway returning a huge `data` array could read it all into
	// memory. The 1MiB cap matches every other response read in this package
	// (do/readLimited) and the authentication-policies payload is tiny.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return false, "", fmt.Errorf("jira: sso-enforcement read body: %w", err)
	}
	var payload struct {
		Data []struct {
			ID         string `json:"id"`
			Attributes struct {
				Name    string `json:"name"`
				SSOOnly bool   `json:"ssoOnly"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return false, "", fmt.Errorf("jira: decode authentication-policies: %w", err)
	}
	for _, p := range payload.Data {
		if p.Attributes.SSOOnly {
			return true, "Atlassian org enforces SSO-only authentication policy", nil
		}
	}
	return false, "Atlassian org allows password sign-in alongside SSO", nil
}
