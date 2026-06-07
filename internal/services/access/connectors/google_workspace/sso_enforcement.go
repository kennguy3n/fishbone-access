package google_workspace

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// CheckSSOEnforcement implements access.SSOEnforcementChecker for
// Google Workspace. It probes /admin/directory/v1/customer/{my_customer}/sso
// (a stable Admin SDK endpoint that mirrors the Admin Console
// "Set up single sign-on for SAML applications" panel) and reports
// enforced=true when the SSO profile is both `enableSSO` AND has a
// non-empty `signInPage` — i.e. the customer has configured a real
// federated IdP sign-in URL, not just toggled the placeholder. (The
// `useDomainSpecificIssuer` flag only controls the issuer format and
// is not a reliable "IdP wired" signal, so it is intentionally not
// part of the decision.)
//
// The "enforced" label here is a coarse "SSO is wired" signal —
// stronger guarantees (e.g. password sign-in fully disabled) live
// in the per-org-unit policy API which is in beta and not stable
// enough to drive an admin-UI assertion against. The
// design accepts this trade-off: the cron sweep that re-runs this
// daily catches regressions even if the signal is coarse.
func (c *GoogleWorkspaceAccessConnector) CheckSSOEnforcement(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (bool, string, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return false, "", err
	}
	client, err := c.directoryClient(ctx, cfg, secrets)
	if err != nil {
		return false, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, directoryBaseURL+"/customer/my_customer/sso", nil)
	if err != nil {
		return false, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, "", fmt.Errorf("google_workspace: sso-enforcement probe: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return false, "", fmt.Errorf("google_workspace: sso-enforcement status %d: %s", resp.StatusCode, string(body))
	}
	var payload struct {
		Enabled    bool   `json:"enableSSO"`
		SignInPage string `json:"signInPage"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return false, "", fmt.Errorf("google_workspace: decode sso profile: %w", err)
	}
	if payload.Enabled && payload.SignInPage != "" {
		return true, "Google Workspace SSO profile is enabled and routed to an external IdP", nil
	}
	return false, "Google Workspace SSO profile is not enabled — operators can still sign in with a Google password", nil
}
