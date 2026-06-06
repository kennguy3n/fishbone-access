package hubspot

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// CheckSSOEnforcement implements access.SSOEnforcementChecker for
// HubSpot. The probe reads the user-provisioning settings via
// GET /settings/v3/users/provisioning and inspects the
// ssoRequired field; the portal is considered SSO-only when SSO
// is enabled AND HubSpot is configured to require it for every
// interactive sign-in (no password fallback for federated users).
//
// Best-effort: a transport or authentication failure returns a
// non-nil err so callers map the connector to "unknown" rather
// than "not_enforced".
func (c *HubSpotAccessConnector) CheckSSOEnforcement(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (bool, string, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return false, "", err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, "/settings/v3/users/provisioning")
	if err != nil {
		return false, "", err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return false, "", fmt.Errorf("hubspot: sso-enforcement probe: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return false, "", fmt.Errorf("hubspot: sso-enforcement status %d: %s", resp.StatusCode, string(body))
	}
	var payload struct {
		SSOEnabled  bool `json:"ssoEnabled"`
		SSORequired bool `json:"ssoRequired"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return false, "", fmt.Errorf("hubspot: decode provisioning settings: %w", err)
	}
	if !payload.SSOEnabled {
		return false, "HubSpot portal does not have SSO enabled", nil
	}
	if !payload.SSORequired {
		return false, "HubSpot portal allows users to sign in without SSO (ssoRequired=false)", nil
	}
	return true, "HubSpot portal requires SSO for every interactive sign-in (ssoRequired=true)", nil
}
