package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// CheckSSOEnforcement implements access.SSOEnforcementChecker for
// GitHub. The org API returns has_organization_projects and a
// two_factor_requirement_enabled flag; the canonical "SSO is
// enforced" signal lives at /orgs/{org}/settings/saml-sso-enabled
// (GraphQL: organization.requiresTwoFactorAuthentication +
// samlIdentityProvider). The probe uses the REST shortcut
// /orgs/{org} which embeds the two_factor flag and a
// has_organization_projects sibling and the GraphQL-equivalent
// "saml_sso_url" present on Enterprise Cloud orgs.
//
// Best-effort: transport / authorisation failures surface as
// non-nil err so callers map them to "unknown".
func (c *GitHubAccessConnector) CheckSSOEnforcement(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (bool, string, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return false, "", err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, c.baseURL()+"/orgs/"+url.PathEscape(cfg.Organization))
	if err != nil {
		return false, "", err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return false, "", fmt.Errorf("github: sso-enforcement probe: %w", err)
	}
	var payload struct {
		TwoFactorRequirementEnabled bool   `json:"two_factor_requirement_enabled"`
		SAMLSSOURL                  string `json:"saml_sso_url"`
	}
	if err := json.Unmarshal(resp.Body, &payload); err != nil {
		return false, "", fmt.Errorf("github: decode org: %w", err)
	}
	if payload.SAMLSSOURL != "" {
		return true, "GitHub org enforces SAML single sign-on", nil
	}
	return false, "GitHub org has no SAML enforcement configured", nil
}
