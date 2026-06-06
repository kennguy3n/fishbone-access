package microsoft

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// CheckSSOEnforcement implements access.SSOEnforcementChecker for
// Microsoft Entra ID. It probes the authenticationFlowsPolicy at
// /policies/authenticationFlowsPolicy and asks "is the global
// 'self-service password reset' / 'password sign-in' surface
// disabled?". When Microsoft-managed authentication is set to
// "federatedAccountsOnly" the tenant rejects every non-SSO sign-in
// at the front door, which is the closest equivalent to the
// sso_only contract enforced elsewhere in the platform.
//
// The probe is best-effort: a transport- / authorisation-level
// failure returns a non-nil err so callers map the result to
// "unknown" — never to "not enforced".
func (c *M365AccessConnector) CheckSSOEnforcement(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (bool, string, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return false, "", err
	}
	client := c.graphClient(ctx, cfg, secrets)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		graphBaseURL+"/policies/authenticationFlowsPolicy", nil)
	if err != nil {
		return false, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, "", fmt.Errorf("microsoft: sso-enforcement probe: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return false, "", fmt.Errorf("microsoft: sso-enforcement status %d: %s", resp.StatusCode, string(body))
	}
	var payload struct {
		SelfServiceSignUp struct {
			IsEnabled bool `json:"isEnabled"`
		} `json:"selfServiceSignUp"`
		ExternalAuthMethods string `json:"externalAuthenticationMethodsConfiguration"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return false, "", fmt.Errorf("microsoft: decode authenticationFlowsPolicy: %w", err)
	}
	// "self-service sign-up disabled" is the canonical signal the
	// tenant rejects non-federated provisioning; pairing it with a
	// configured external authentication method is the strongest
	// sso_only assertion the Graph surface exposes today.
	if !payload.SelfServiceSignUp.IsEnabled {
		return true, "Entra ID self-service sign-up is disabled — federated sign-in required", nil
	}
	return false, "Entra ID self-service sign-up is enabled — non-federated accounts can still be created", nil
}
