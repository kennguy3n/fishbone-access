package ping_identity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// CheckSSOEnforcement implements access.SSOEnforcementChecker for
// PingOne. The probe reads the environment's configured sign-on
// policies via GET /v1/environments/{envID}/signOnPolicies, locates
// the default policy, then fetches its sign-on actions via
// GET /v1/environments/{envID}/signOnPolicies/{policyID}/actions
// and verifies that every action enforces a federated identity
// provider (type == IDENTITY_PROVIDER) with no fallback LOGIN action
// (which would allow username + password sign-in). The tenant is
// considered SSO-only when the default policy has at least one
// IDENTITY_PROVIDER action and zero LOGIN actions.
//
// Best-effort: a transport or authentication failure returns a
// non-nil err so callers map the connector to "unknown" rather
// than "not_enforced". A policy that only declares MFA / agreement
// / progressive-profiling actions (and no first-factor LOGIN or
// IDENTITY_PROVIDER) is reported as not enforced because the
// first-factor path remains unspecified.
func (c *PingIdentityAccessConnector) CheckSSOEnforcement(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (bool, string, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return false, "", err
	}
	token, err := c.fetchAccessToken(ctx, cfg, secrets)
	if err != nil {
		return false, "", fmt.Errorf("ping_identity: sso-enforcement: authenticate: %w", err)
	}
	policies, err := c.listSignOnPolicies(ctx, cfg, token)
	if err != nil {
		return false, "", err
	}
	if len(policies) == 0 {
		return false, "PingOne environment has no sign-on policies — federation cannot be enforced", nil
	}
	var defaultPolicy signOnPolicy
	for _, p := range policies {
		if p.Default {
			defaultPolicy = p
			break
		}
	}
	if defaultPolicy.ID == "" {
		return false, "PingOne environment has no default sign-on policy — fallback sign-in path remains open", nil
	}
	actions, err := c.listSignOnPolicyActions(ctx, cfg, token, defaultPolicy.ID)
	if err != nil {
		return false, "", err
	}
	if len(actions) == 0 {
		return false, fmt.Sprintf(
			"PingOne default sign-on policy %q has no actions configured — first-factor sign-in path remains open",
			defaultPolicy.Name,
		), nil
	}
	var (
		idpCount   int
		loginCount int
	)
	for _, a := range actions {
		switch a.Type {
		case "IDENTITY_PROVIDER":
			idpCount++
		case "LOGIN":
			loginCount++
		}
	}
	if loginCount > 0 {
		return false, fmt.Sprintf(
			"PingOne default sign-on policy %q permits %d username+password LOGIN action(s) — SSO is not enforced",
			defaultPolicy.Name, loginCount,
		), nil
	}
	if idpCount == 0 {
		return false, fmt.Sprintf(
			"PingOne default sign-on policy %q has no IDENTITY_PROVIDER action — first-factor federation is not enforced",
			defaultPolicy.Name,
		), nil
	}
	return true, fmt.Sprintf(
		"PingOne default sign-on policy %q enforces %d IDENTITY_PROVIDER action(s) with no LOGIN fallback",
		defaultPolicy.Name, idpCount,
	), nil
}

type signOnPolicy struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Default     bool   `json:"default"`
	Description string `json:"description,omitempty"`
	PolicyType  string `json:"policyType,omitempty"`
}

type signOnPolicyAction struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Priority int    `json:"priority,omitempty"`
}

func (c *PingIdentityAccessConnector) listSignOnPolicies(ctx context.Context, cfg Config, token string) ([]signOnPolicy, error) {
	fullURL := c.apiURL(cfg, fmt.Sprintf(
		"/v1/environments/%s/signOnPolicies",
		url.PathEscape(cfg.EnvironmentID),
	))
	req, err := newAuthedRequest(ctx, fullURL, token)
	if err != nil {
		return nil, err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return nil, fmt.Errorf("ping_identity: sso-enforcement probe: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("ping_identity: sso-enforcement status %d: %s", resp.StatusCode, string(body))
	}
	var payload struct {
		Embedded struct {
			SignOnPolicies []signOnPolicy `json:"signOnPolicies"`
		} `json:"_embedded"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("ping_identity: decode signOnPolicies: %w", err)
	}
	return payload.Embedded.SignOnPolicies, nil
}

func (c *PingIdentityAccessConnector) listSignOnPolicyActions(ctx context.Context, cfg Config, token, policyID string) ([]signOnPolicyAction, error) {
	fullURL := c.apiURL(cfg, fmt.Sprintf(
		"/v1/environments/%s/signOnPolicies/%s/actions",
		url.PathEscape(cfg.EnvironmentID),
		url.PathEscape(policyID),
	))
	req, err := newAuthedRequest(ctx, fullURL, token)
	if err != nil {
		return nil, err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return nil, fmt.Errorf("ping_identity: sso-enforcement actions probe: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("ping_identity: sso-enforcement actions status %d: %s", resp.StatusCode, string(body))
	}
	var payload struct {
		Embedded struct {
			Actions []signOnPolicyAction `json:"actions"`
		} `json:"_embedded"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("ping_identity: decode signOnPolicyActions: %w", err)
	}
	return payload.Embedded.Actions, nil
}
