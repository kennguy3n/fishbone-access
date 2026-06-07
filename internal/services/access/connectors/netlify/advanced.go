package netlify

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

// advanced-capability mapping for netlify:
//
//   - ProvisionAccess  -> POST   /api/v1/{account_slug}/members
//   - RevokeAccess     -> DELETE /api/v1/{account_slug}/members/{member_id}
//   - ListEntitlements -> GET    /api/v1/{account_slug}/members
//
// Bearer auth via connector.newRequest. Idempotent on
// (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func netlifyValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("netlify: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("netlify: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *NetlifyAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("netlify: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *NetlifyAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

func (c *NetlifyAccessConnector) membersURL(slug string) string {
	return c.baseURL() + c.membersPath(slug)
}

func (c *NetlifyAccessConnector) memberURL(slug, member string) string {
	return c.membersURL(slug) + "/" + url.PathEscape(strings.TrimSpace(member))
}

func (c *NetlifyAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := netlifyValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	if strings.TrimSpace(cfg.AccountSlug) == "" {
		return errors.New("netlify: account_slug is required for ProvisionAccess")
	}
	payload, _ := json.Marshal(map[string]string{
		"email": strings.TrimSpace(grant.UserExternalID),
		"role":  strings.TrimSpace(grant.ResourceExternalID),
	})
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, c.membersURL(cfg.AccountSlug), payload)
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
		return fmt.Errorf("netlify: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("netlify: provision status %d: %s", status, string(body))
	}
}

func (c *NetlifyAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := netlifyValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	if strings.TrimSpace(cfg.AccountSlug) == "" {
		return errors.New("netlify: account_slug is required for RevokeAccess")
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete,
		c.memberURL(cfg.AccountSlug, grant.UserExternalID), nil)
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
		return fmt.Errorf("netlify: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("netlify: revoke status %d: %s", status, string(body))
	}
}

func (c *NetlifyAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("netlify: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.AccountSlug) == "" {
		return nil, nil
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, c.membersURL(cfg.AccountSlug), nil)
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
		return nil, fmt.Errorf("netlify: list entitlements status %d: %s", status, string(body))
	}
	var members []struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := json.Unmarshal(body, &members); err != nil {
		return nil, fmt.Errorf("netlify: decode entitlements: %w", err)
	}
	out := make([]access.Entitlement, 0, len(members))
	for _, m := range members {
		if m.ID != user && !strings.EqualFold(m.Email, user) {
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
