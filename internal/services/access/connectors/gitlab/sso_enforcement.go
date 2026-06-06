package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// CheckSSOEnforcement implements access.SSOEnforcementChecker for
// GitLab. The /api/v4/application/settings endpoint exposes the
// instance-wide `password_authentication_enabled_for_web` and
// `password_authentication_enabled_for_git` toggles; when both are
// false the platform admin has fully enforced SSO-only authentication.
//
// Best-effort: transport / authorisation failures surface as a
// non-nil err so callers map them to "unknown" — never to "not
// enforced".
func (c *GitLabAccessConnector) CheckSSOEnforcement(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (bool, string, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return false, "", err
	}
	endpoint := c.baseURL(cfg) + "/api/v4/application/settings"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, endpoint)
	if err != nil {
		return false, "", err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return false, "", fmt.Errorf("gitlab: sso-enforcement probe: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return false, "", fmt.Errorf("gitlab: sso-enforcement status %d: %s", resp.StatusCode, string(body))
	}
	var settings struct {
		PasswordAuthWeb bool `json:"password_authentication_enabled_for_web"`
		PasswordAuthGit bool `json:"password_authentication_enabled_for_git"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&settings); err != nil {
		return false, "", fmt.Errorf("gitlab: decode application settings: %w", err)
	}
	if !settings.PasswordAuthWeb && !settings.PasswordAuthGit {
		return true, "Password sign-in disabled for both web and git on this GitLab instance", nil
	}
	return false, "GitLab still permits password sign-in (web or git)", nil
}
