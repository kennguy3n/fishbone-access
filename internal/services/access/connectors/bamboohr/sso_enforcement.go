package bamboohr

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// CheckSSOEnforcement implements access.SSOEnforcementChecker for
// BambooHR. The probe reads the security metadata via
// GET /v1/meta/security and inspects the sso_only flag (true
// means every interactive sign-in must round-trip the federated
// IdP; false means a BambooHR password fallback is available).
//
// Best-effort: a transport or authentication failure returns a
// non-nil err so callers map the connector to "unknown" rather
// than "not_enforced".
func (c *BambooHRAccessConnector) CheckSSOEnforcement(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (bool, string, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return false, "", err
	}
	fullURL := c.baseURL(cfg) + "/v1/meta/security"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
	if err != nil {
		return false, "", err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return false, "", fmt.Errorf("bamboohr: sso-enforcement probe: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return false, "", fmt.Errorf("bamboohr: sso-enforcement status %d: %s", resp.StatusCode, string(body))
	}
	var payload struct {
		SSOOnly bool `json:"sso_only"`
		SSO     struct {
			Enabled bool `json:"enabled"`
		} `json:"sso"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return false, "", fmt.Errorf("bamboohr: decode security meta: %w", err)
	}
	if !payload.SSO.Enabled {
		return false, "BambooHR account does not have SSO enabled at all", nil
	}
	if !payload.SSOOnly {
		return false, "BambooHR account allows employees to sign in with a BambooHR password (sso_only=false)", nil
	}
	return true, "BambooHR account requires SSO for every employee sign-in (sso_only=true)", nil
}
