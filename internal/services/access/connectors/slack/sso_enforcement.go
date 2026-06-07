package slack

import (
	"context"
	"encoding/json"
	"fmt"
)

// CheckSSOEnforcement implements access.SSOEnforcementChecker for
// Slack. The /api/team.info endpoint returns the workspace's
// SSO-mode flag (sso_provider.type=="saml" combined with
// enterprise.is_sso_enabled). When the workspace has SAML
// configured AND password sign-in is disabled the connector
// reports enforced=true.
//
// Best-effort: transport / authorisation failures surface as
// non-nil err so callers map them to "unknown".
func (c *SlackAccessConnector) CheckSSOEnforcement(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (bool, string, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return false, "", err
	}
	req, err := c.newRequest(ctx, secrets, "GET", "/team.info")
	if err != nil {
		return false, "", err
	}
	body, apiErr, err := c.doWithAPIError(req)
	if err != nil {
		return false, "", fmt.Errorf("slack: sso-enforcement probe: %w", err)
	}
	if apiErr != "" {
		return false, "", fmt.Errorf("slack: sso-enforcement api error: %s", apiErr)
	}
	var payload struct {
		Team struct {
			SSOProvider struct {
				Type string `json:"type"`
			} `json:"sso_provider"`
			DiscoverableState string `json:"discoverable"`
		} `json:"team"`
		Enterprise struct {
			IsSSOEnabled bool `json:"is_sso_enabled"`
		} `json:"enterprise"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return false, "", fmt.Errorf("slack: decode team.info: %w", err)
	}
	// SSO is only *enforced* when a SAML provider is wired AND the
	// workspace has SSO sign-in enabled (password sign-in disabled). A
	// configured provider alone is not sufficient: a workspace can have
	// SAML available while still permitting password login, in which case
	// access is not actually gated behind the IdP. Reporting enforced=true
	// in that case is a false positive that masks a real security
	// regression for the connector-health endpoint and orphan-account
	// reconciler, so both signals are required (matching slack_enterprise).
	if payload.Team.SSOProvider.Type == "saml" && payload.Enterprise.IsSSOEnabled {
		return true, "Slack workspace is wired to a SAML identity provider and password sign-in is disabled", nil
	}
	return false, "Slack workspace allows password sign-in alongside SSO", nil
}
