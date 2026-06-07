package workday

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// CheckSSOEnforcement implements access.SSOEnforcementChecker for
// Workday. The probe reads the authentication policy via
// GET /api/authentication/v1/policies and inspects the
// authenticationGateway field; the tenant is considered SSO-only
// when the workday native (password) gateway is disabled and a
// SAML / OIDC gateway is the only active option.
//
// Best-effort: a transport or authentication failure returns a
// non-nil err so callers map the connector to "unknown" rather
// than "not_enforced".
func (c *WorkdayAccessConnector) CheckSSOEnforcement(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (bool, string, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return false, "", err
	}
	fullURL := c.baseURL(cfg) + "/api/authentication/v1/policies"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
	if err != nil {
		return false, "", err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return false, "", fmt.Errorf("workday: sso-enforcement probe: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return false, "", fmt.Errorf("workday: sso-enforcement status %d: %s", resp.StatusCode, string(body))
	}
	var payload struct {
		Data []struct {
			Name                   string `json:"name"`
			Active                 bool   `json:"active"`
			RequireFederatedAuth   bool   `json:"requireFederatedAuthentication"`
			AllowsPasswordFallback bool   `json:"allowsPasswordFallback"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return false, "", fmt.Errorf("workday: decode authentication policies: %w", err)
	}
	if len(payload.Data) == 0 {
		return false, "Workday tenant has no authentication policies configured — sign-on cannot be enforced", nil
	}
	hasActivePolicy := false
	for _, p := range payload.Data {
		if !p.Active {
			continue
		}
		hasActivePolicy = true
		if p.AllowsPasswordFallback || !p.RequireFederatedAuth {
			return false, fmt.Sprintf(
				"Workday authentication policy %q still allows password fallback",
				p.Name,
			), nil
		}
	}
	if !hasActivePolicy {
		return false, "Workday tenant has no active authentication policies — sign-on cannot be enforced", nil
	}
	return true, "Workday authentication policies all require federated SSO for sign-in", nil
}
