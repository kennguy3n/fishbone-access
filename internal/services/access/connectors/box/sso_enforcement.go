package box

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// CheckSSOEnforcement implements access.SSOEnforcementChecker for
// Box. /2.0/users/me?fields=enterprise returns the caller's
// enterprise envelope including the `sso_required` flag that the
// admin console toggles when the enterprise enforces SAML / OIDC
// for all managed users (Box Enterprise Plus and above).
//
// Best-effort: transport / authorisation failures surface as a
// non-nil err so callers map them to "unknown" — never to "not
// enforced".
func (c *BoxAccessConnector) CheckSSOEnforcement(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (bool, string, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return false, "", err
	}
	endpoint := c.baseURL() + "/2.0/users/me?fields=enterprise"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, endpoint)
	if err != nil {
		return false, "", err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return false, "", fmt.Errorf("box: sso-enforcement probe: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return false, "", fmt.Errorf("box: sso-enforcement status %d: %s", resp.StatusCode, string(body))
	}
	var payload struct {
		Enterprise struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			SSORequired bool   `json:"sso_required"`
		} `json:"enterprise"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return false, "", fmt.Errorf("box: decode enterprise envelope: %w", err)
	}
	if payload.Enterprise.SSORequired {
		return true, "Box enterprise has SSO-required toggle enabled", nil
	}
	return false, "Box enterprise still permits non-SSO sign-in", nil
}
