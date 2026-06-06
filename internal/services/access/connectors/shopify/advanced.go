package shopify

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

// advanced-capability mapping for shopify:
//
//   - ProvisionAccess  -> POST   /admin/api/2024-01/users.json        (invite staff member)
//   - RevokeAccess     -> DELETE /admin/api/2024-01/users/{id}.json   (remove staff member)
//   - ListEntitlements -> GET    /admin/api/2024-01/users/{id}.json   (account_owner + role)
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Shopify staff numeric id or email
//   - grant.ResourceExternalID -> role slug (e.g. "admin", "limited", "collaborator")
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func shopifyValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("shopify: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("shopify: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *ShopifyAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("shopify: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *ShopifyAccessConnector) usersURL(cfg Config) string {
	return c.baseURL(cfg) + "/admin/api/2024-01/users.json"
}

func (c *ShopifyAccessConnector) userURL(cfg Config, userID string) string {
	return c.baseURL(cfg) + "/admin/api/2024-01/users/" + url.PathEscape(strings.TrimSpace(userID)) + ".json"
}

func (c *ShopifyAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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
	req.Header.Set("X-Shopify-Access-Token", strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *ShopifyAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := shopifyValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	role := strings.TrimSpace(grant.ResourceExternalID)
	payload, _ := json.Marshal(map[string]interface{}{
		"user": map[string]interface{}{
			"email": strings.TrimSpace(grant.UserExternalID),
			"role":  role,
		},
	})
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, c.usersURL(cfg), payload)
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
		return fmt.Errorf("shopify: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("shopify: provision status %d: %s", status, string(body))
	}
}

func (c *ShopifyAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := shopifyValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete, c.userURL(cfg, grant.UserExternalID), nil)
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
		return fmt.Errorf("shopify: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("shopify: revoke status %d: %s", status, string(body))
	}
}

func (c *ShopifyAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("shopify: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, c.userURL(cfg, user), nil)
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
		return nil, fmt.Errorf("shopify: list entitlements status %d: %s", status, string(body))
	}
	var resp struct {
		User struct {
			ID           json.Number `json:"id"`
			Email        string      `json:"email"`
			Role         string      `json:"role"`
			AccountOwner bool        `json:"account_owner"`
		} `json:"user"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("shopify: decode entitlements: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(resp.User.Email), user) &&
		strings.TrimSpace(resp.User.ID.String()) != user {
		return nil, nil
	}
	role := strings.TrimSpace(resp.User.Role)
	if resp.User.AccountOwner {
		role = "account_owner"
	}
	if role == "" {
		return []access.Entitlement{}, nil
	}
	return []access.Entitlement{{
		ResourceExternalID: role,
		Role:               role,
		Source:             "direct",
	}}, nil
}
