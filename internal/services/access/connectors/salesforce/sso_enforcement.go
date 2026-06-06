package salesforce

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// CheckSSOEnforcement implements access.SSOEnforcementChecker for
// Salesforce. The Tooling API exposes SecuritySettings which
// records whether the org requires single sign-on for every
// interactive login. The probe queries
// /services/data/v59.0/tooling/query?q=SELECT+RequireSingleSignOn+FROM+SecuritySettings
// and reports enforced=true iff at least one row has
// RequireSingleSignOn = true.
//
// Best-effort: transport / authorisation failures surface as
// non-nil err so callers map them to "unknown".
func (c *SalesforceAccessConnector) CheckSSOEnforcement(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (bool, string, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return false, "", err
	}
	fullURL := c.instanceBase(cfg) + "/services/data/v59.0/tooling/query?q=" +
		"SELECT+RequireSingleSignOn+FROM+SecuritySettings"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
	if err != nil {
		return false, "", err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return false, "", fmt.Errorf("salesforce: sso-enforcement probe: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return false, "", fmt.Errorf("salesforce: sso-enforcement status %d: %s", resp.StatusCode, string(body))
	}
	var payload struct {
		Records []struct {
			RequireSingleSignOn bool `json:"RequireSingleSignOn"`
		} `json:"records"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return false, "", fmt.Errorf("salesforce: decode SecuritySettings: %w", err)
	}
	for _, r := range payload.Records {
		if r.RequireSingleSignOn {
			return true, "Salesforce org requires single sign-on for every interactive login", nil
		}
	}
	return false, "Salesforce org allows password login alongside SSO", nil
}
