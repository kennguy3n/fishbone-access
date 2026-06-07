package bigcommerce

import (
	"bytes"
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

// advanced-capability mapping for BigCommerce:
//
//   - ProvisionAccess  -> POST   /stores/{store_hash}/v2/users
//   - RevokeAccess     -> DELETE /stores/{store_hash}/v2/users/{id}
//   - ListEntitlements -> GET    /stores/{store_hash}/v2/users/{id}
//
// AccessGrant maps:
//   - grant.UserExternalID     -> BigCommerce user numeric id or email
//   - grant.ResourceExternalID -> role / permission set name
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func bigcommerceValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("bigcommerce: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("bigcommerce: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *BigCommerceAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("bigcommerce: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *BigCommerceAccessConnector) usersURL(cfg Config) string {
	return c.baseURL() + "/stores/" + url.PathEscape(strings.TrimSpace(cfg.StoreHash)) + "/v2/users"
}

func (c *BigCommerceAccessConnector) userURL(cfg Config, userID string) string {
	return c.baseURL() + "/stores/" + url.PathEscape(strings.TrimSpace(cfg.StoreHash)) + "/v2/users/" + url.PathEscape(strings.TrimSpace(userID))
}

func (c *BigCommerceAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	var rdr io.Reader
	if len(body) > 0 {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Auth-Token", strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *BigCommerceAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := bigcommerceValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"email": strings.TrimSpace(grant.UserExternalID),
		"role":  strings.TrimSpace(grant.ResourceExternalID),
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
		return fmt.Errorf("bigcommerce: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("bigcommerce: provision status %d: %s", status, string(body))
	}
}

func (c *BigCommerceAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := bigcommerceValidateGrant(grant); err != nil {
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
		return fmt.Errorf("bigcommerce: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("bigcommerce: revoke status %d: %s", status, string(body))
	}
}

func (c *BigCommerceAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("bigcommerce: user external id is required")
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
		return nil, fmt.Errorf("bigcommerce: list entitlements status %d: %s", status, string(body))
	}
	var resp struct {
		ID    json.Number `json:"id"`
		Email string      `json:"email"`
		Role  string      `json:"role"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("bigcommerce: decode entitlements: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(resp.Email), user) &&
		strings.TrimSpace(resp.ID.String()) != user {
		return nil, nil
	}
	role := strings.TrimSpace(resp.Role)
	if role == "" {
		return []access.Entitlement{}, nil
	}
	return []access.Entitlement{{
		ResourceExternalID: role,
		Role:               role,
		Source:             "direct",
	}}, nil
}
