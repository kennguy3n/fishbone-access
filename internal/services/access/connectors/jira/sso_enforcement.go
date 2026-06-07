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
	// json.NewDecoder below only consumes one JSON value and leaves any
	// trailing bytes unread, so a plain Close would prevent net/http from
	// returning the connection to the keep-alive pool. Drain first, matching
	// the write paths in connector.go / session_revoke.go.
	defer drainAndClose(resp)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return false, "", fmt.Errorf("jira: sso-enforcement status %d: %s", resp.StatusCode, string(body))
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
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return false, "", fmt.Errorf("jira: decode authentication-policies: %w", err)
	}
	for _, p := range payload.Data {
		if p.Attributes.SSOOnly {
			return true, "Atlassian org enforces SSO-only authentication policy", nil
		}
	}
	return false, "Atlassian org allows password sign-in alongside SSO", nil
}
