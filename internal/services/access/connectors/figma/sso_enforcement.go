package figma

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// CheckSSOEnforcement implements access.SSOEnforcementChecker for
// Figma. Figma Enterprise exposes per-organisation security settings
// at `GET /v1/organizations/{org_id}` which include `sso_required`
// (forces every member to sign in via the configured SAML IdP). When
// the org has SSO required, the connector reports enforced=true.
//
// Best-effort: transport / authorisation failures surface as a
// non-nil err so callers map them to "unknown" — never to "not
// enforced".
func (c *FigmaAccessConnector) CheckSSOEnforcement(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (bool, string, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return false, "", err
	}
	orgID, _ := configRaw["org_id"].(string)
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return false, "", fmt.Errorf("figma: sso-enforcement: org_id is required")
	}
	endpoint := "/organizations/" + url.PathEscape(orgID)
	req, err := c.newRequest(ctx, secrets, http.MethodGet, endpoint)
	if err != nil {
		return false, "", err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return false, "", fmt.Errorf("figma: sso-enforcement probe: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return false, "", fmt.Errorf("figma: sso-enforcement status %d: %s", resp.StatusCode, string(body))
	}
	var payload struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		SSORequired bool   `json:"sso_required"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return false, "", fmt.Errorf("figma: decode organization payload: %w", err)
	}
	if payload.SSORequired {
		return true, "Figma organization requires SAML SSO sign-in", nil
	}
	return false, "Figma organization permits non-SSO sign-in", nil
}
