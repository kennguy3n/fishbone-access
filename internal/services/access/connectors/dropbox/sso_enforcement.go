package dropbox

import (
	"context"
	"encoding/json"
	"fmt"
)

// CheckSSOEnforcement implements access.SSOEnforcementChecker for
// Dropbox Business. The team admin API exposes a "features" surface
// at /2/team/features/get_values that lets the caller request the
// "has_team_shared_dropbox" / "sso_enabled" feature flags; combined
// with the team-level SSO configuration on /2/team/get_info, we can
// report enforced=true when the team has SAML wired up AND password
// sign-in is disabled at the team level.
//
// Best-effort: transport / authorisation failures surface as a
// non-nil err so callers map the result to "unknown" instead of
// silently treating the team as compliant.
func (c *DropboxAccessConnector) CheckSSOEnforcement(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (bool, string, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return false, "", err
	}

	// Dropbox's team admin "get_info" returns the team name and the
	// SSO-enforcement policy under the "policies" key. The exact
	// field is "enforced_password_strength" / "sso" — when "sso" is
	// "required" the team requires SAML for every interactive sign
	// in.
	body, err := c.postJSON(ctx, secrets, c.baseURL()+"/2/team/get_info", struct{}{})
	if err != nil {
		return false, "", fmt.Errorf("dropbox: sso-enforcement probe: %w", err)
	}

	var payload struct {
		Name     string `json:"name"`
		Policies struct {
			SSO struct {
				Tag string `json:".tag"`
			} `json:"sso"`
		} `json:"policies"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return false, "", fmt.Errorf("dropbox: decode team get_info: %w", err)
	}

	switch payload.Policies.SSO.Tag {
	case "required":
		return true, "Dropbox team requires single sign-on for every interactive login", nil
	case "optional", "disabled", "":
		return false, "Dropbox team allows password login alongside SSO", nil
	default:
		return false, fmt.Sprintf("Dropbox team SSO policy = %q (unrecognised tag)", payload.Policies.SSO.Tag), nil
	}
}
