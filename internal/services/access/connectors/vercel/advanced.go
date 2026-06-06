package vercel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// advanced-capability mapping for vercel:
//
//   - ProvisionAccess  -> POST   /v1/teams/{teamId}/members
//   - RevokeAccess     -> DELETE /v1/teams/{teamId}/members/{userId}
//   - ListEntitlements -> GET    /v1/teams/{teamId}/members
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.
// The Vercel team ID is read from Config.TeamID; ResourceExternalID
// carries the team role (MEMBER|DEVELOPER|VIEWER|BILLING|OWNER).

func vercelValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("vercel: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("vercel: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *VercelAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("vercel: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *VercelAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	var rdr io.Reader
	if len(body) > 0 {
		rdr = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.APIToken))
	return req, nil
}

func (c *VercelAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := vercelValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	if strings.TrimSpace(cfg.TeamID) == "" {
		return errors.New("vercel: team_id is required for ProvisionAccess")
	}
	payload, _ := json.Marshal(map[string]string{
		"uid":  strings.TrimSpace(grant.UserExternalID),
		"role": strings.TrimSpace(grant.ResourceExternalID),
	})
	endpoint := c.baseURL() + "/v1/teams/" + url.PathEscape(cfg.TeamID) + "/members"
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, endpoint, payload)
	if err != nil {
		return err
	}
	status, body, err := c.doRaw(req)
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case access.IsIdempotentProvisionStatus(status, body):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("vercel: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("vercel: provision status %d: %s", status, string(body))
	}
}

func (c *VercelAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := vercelValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	if strings.TrimSpace(cfg.TeamID) == "" {
		return errors.New("vercel: team_id is required for RevokeAccess")
	}
	endpoint := c.baseURL() + "/v1/teams/" + url.PathEscape(cfg.TeamID) + "/members/" + url.PathEscape(strings.TrimSpace(grant.UserExternalID))
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}
	status, body, err := c.doRaw(req)
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case access.IsIdempotentRevokeStatus(status, body):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("vercel: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("vercel: revoke status %d: %s", status, string(body))
	}
}

func (c *VercelAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("vercel: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.TeamID) == "" {
		return nil, nil
	}
	endpoint := c.baseURL() + "/v1/teams/" + url.PathEscape(cfg.TeamID) + "/members"
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	status, body, err := c.doRaw(req)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("vercel: list entitlements status %d: %s", status, string(body))
	}
	var envelope struct {
		Members []struct {
			UID      string `json:"uid"`
			Email    string `json:"email"`
			Role     string `json:"role"`
			Username string `json:"username"`
		} `json:"members"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("vercel: decode entitlements: %w", err)
	}
	out := make([]access.Entitlement, 0, len(envelope.Members))
	for _, m := range envelope.Members {
		if m.UID != user && !strings.EqualFold(m.Email, user) && !strings.EqualFold(m.Username, user) {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: strings.TrimSpace(m.Role),
			Role:               strings.TrimSpace(m.Role),
			Source:             "direct",
		})
	}
	return out, nil
}
