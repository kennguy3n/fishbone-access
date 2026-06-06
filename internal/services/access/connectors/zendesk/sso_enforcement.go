package zendesk

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"context"
)

// CheckSSOEnforcement implements access.SSOEnforcementChecker for
// Zendesk. The probe reads the account settings via
// GET /api/v2/account/settings.json and inspects the
// security.sso_bypass_disabled field (true means agents are
// forced to round-trip the federated IdP; false means a local
// password fallback is available).
//
// Best-effort: a transport or authentication failure returns a
// non-nil err so callers map the connector to "unknown" rather
// than "not_enforced".
func (c *ZendeskAccessConnector) CheckSSOEnforcement(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (bool, string, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return false, "", err
	}
	fullURL := c.baseURL(cfg) + "/api/v2/account/settings.json"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
	if err != nil {
		return false, "", err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return false, "", fmt.Errorf("zendesk: sso-enforcement probe: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return false, "", fmt.Errorf("zendesk: sso-enforcement status %d: %s", resp.StatusCode, string(body))
	}
	var payload struct {
		Settings struct {
			Security struct {
				SSOBypassDisabled bool `json:"sso_bypass_disabled"`
				SAMLLoginEnabled  bool `json:"saml_login_enabled"`
			} `json:"security"`
			Active struct {
				SSO bool `json:"sso"`
			} `json:"active"`
		} `json:"settings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return false, "", fmt.Errorf("zendesk: decode settings: %w", err)
	}
	if !payload.Settings.Security.SAMLLoginEnabled && !payload.Settings.Active.SSO {
		return false, "Zendesk account does not have SAML / SSO enabled at all", nil
	}
	if !payload.Settings.Security.SSOBypassDisabled {
		return false, "Zendesk account allows agents to bypass SSO with a local password (sso_bypass_disabled=false)", nil
	}
	return true, "Zendesk account requires SSO for every agent sign-in (sso_bypass_disabled=true)", nil
}
