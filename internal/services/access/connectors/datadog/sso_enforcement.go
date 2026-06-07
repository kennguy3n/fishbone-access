package datadog

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// CheckSSOEnforcement implements access.SSOEnforcementChecker for
// Datadog. The org settings API at GET /api/v1/org returns a
// `settings` object that includes both `saml.enabled` and
// `saml_strict_mode.enabled`. SSO is considered enforced when both
// SAML is enabled AND strict mode is on — strict mode disables the
// non-SSO username/password sign-in path.
//
// Best-effort: transport / authorisation failures surface as a
// non-nil err so callers map the result to "unknown" instead of
// silently treating the account as compliant.
func (c *DatadogAccessConnector) CheckSSOEnforcement(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (bool, string, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return false, "", err
	}
	endpoint := c.baseURL(cfg) + "/api/v1/org"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, endpoint)
	if err != nil {
		return false, "", err
	}
	body, err := c.do(req)
	if err != nil {
		return false, "", fmt.Errorf("datadog: sso-enforcement probe: %w", err)
	}
	var payload struct {
		Org struct {
			Settings struct {
				SAML struct {
					Enabled bool `json:"enabled"`
				} `json:"saml"`
				SAMLStrict struct {
					Enabled bool `json:"enabled"`
				} `json:"saml_strict_mode"`
				SAMLAutocreate struct {
					Enabled bool `json:"enabled"`
				} `json:"saml_autocreate_users_domains"`
			} `json:"settings"`
		} `json:"org"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return false, "", fmt.Errorf("datadog: decode org settings: %w", err)
	}
	s := payload.Org.Settings
	switch {
	case s.SAML.Enabled && s.SAMLStrict.Enabled:
		return true, "Datadog org has SAML enabled with strict mode (no password fallback)", nil
	case s.SAML.Enabled && !s.SAMLStrict.Enabled:
		return false, "Datadog org has SAML enabled but strict mode is off; password login still allowed", nil
	default:
		return false, "Datadog org does not have SAML enabled", nil
	}
}

var _ access.SSOEnforcementChecker = (*DatadogAccessConnector)(nil)
