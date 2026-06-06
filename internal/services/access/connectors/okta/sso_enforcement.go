package okta

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// CheckSSOEnforcement implements access.SSOEnforcementChecker.
// It walks the Okta sign-on policy rules at /api/v1/policies?type=OKTA_SIGN_ON
// and reports enforced=true when at least one ACTIVE rule denies
// authentication when the federated IdP cannot satisfy it (i.e.
// "FEDERATED" requirement). Otherwise reports enforced=false with
// a short hint suitable for the admin UI.
//
// Best-effort semantics per the contract: a transport-
// or authorisation-level failure returns a non-nil err so callers
// surface the result as "unknown" — never as "not enforced".
func (c *OktaAccessConnector) CheckSSOEnforcement(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (bool, string, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return false, "", err
	}
	req, err := c.newRequest(ctx, cfg, secrets, http.MethodGet, "/api/v1/policies?type=OKTA_SIGN_ON", nil)
	if err != nil {
		return false, "", err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return false, "", fmt.Errorf("okta: sso-enforcement probe: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return false, "", fmt.Errorf("okta: sso-enforcement status %d: %s", resp.StatusCode, string(body))
	}
	var policies []struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&policies); err != nil {
		return false, "", fmt.Errorf("okta: decode sso-enforcement policies: %w", err)
	}
	enforced, details := c.evaluateSignOnPolicies(ctx, cfg, secrets, policies)
	return enforced, details, nil
}

// evaluateSignOnPolicies fans out one HTTP call per active policy
// to /policies/{id}/rules and decides whether at least one active
// rule requires federation. Kept separate so the test fixture can
// drive the rule shape without re-running the full HTTP discovery.
func (c *OktaAccessConnector) evaluateSignOnPolicies(
	ctx context.Context,
	cfg Config,
	secrets Secrets,
	policies []struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	},
) (bool, string) {
	for _, p := range policies {
		if p.Status != "ACTIVE" {
			continue
		}
		req, err := c.newRequest(ctx, cfg, secrets, http.MethodGet, "/api/v1/policies/"+url.PathEscape(p.ID)+"/rules", nil)
		if err != nil {
			continue
		}
		raw, err := c.do(req)
		if err != nil {
			continue
		}
		var rules []struct {
			Status  string `json:"status"`
			Actions struct {
				SignOn struct {
					Requirements struct {
						Factor string `json:"factor"`
					} `json:"requireFactor"`
				} `json:"signon"`
			} `json:"actions"`
		}
		if err := json.Unmarshal(raw, &rules); err != nil {
			continue
		}
		for _, r := range rules {
			if r.Status != "ACTIVE" {
				continue
			}
			if r.Actions.SignOn.Requirements.Factor == "FEDERATED" {
				return true, "SSO-only sign-on policy enforced"
			}
		}
	}
	return false, "Password sign-on still permitted by active Okta sign-on policy rules"
}
