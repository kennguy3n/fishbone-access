package woocommerce

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// advanced-capability mapping for WooCommerce:
//
//   - ProvisionAccess  -> POST   /wp-json/wc/v3/customers
//   - RevokeAccess     -> DELETE /wp-json/wc/v3/customers/{id}?force=true
//   - ListEntitlements -> GET    /wp-json/wc/v3/customers/{id}
//
// AccessGrant maps:
//   - grant.UserExternalID     -> WooCommerce customer numeric id or email
//   - grant.ResourceExternalID -> WordPress role name (e.g. "customer", "shop_manager")
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func woocommerceValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("woocommerce: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("woocommerce: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *WooCommerceAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("woocommerce: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *WooCommerceAccessConnector) customersURL(cfg Config) string {
	return c.baseURL(cfg) + "/wp-json/wc/v3/customers"
}

func (c *WooCommerceAccessConnector) customerURL(cfg Config, userID string) string {
	return c.baseURL(cfg) + "/wp-json/wc/v3/customers/" + url.PathEscape(strings.TrimSpace(userID))
}

func (c *WooCommerceAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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
	creds := strings.TrimSpace(secrets.ConsumerKey) + ":" + strings.TrimSpace(secrets.ConsumerSecret)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	return req, nil
}

func (c *WooCommerceAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := woocommerceValidateGrant(grant); err != nil {
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
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, c.customersURL(cfg), payload)
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
		return fmt.Errorf("woocommerce: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("woocommerce: provision status %d: %s", status, string(body))
	}
}

func (c *WooCommerceAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := woocommerceValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete, c.customerURL(cfg, grant.UserExternalID)+"?force=true", nil)
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
		return fmt.Errorf("woocommerce: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("woocommerce: revoke status %d: %s", status, string(body))
	}
}

func (c *WooCommerceAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("woocommerce: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, c.customerURL(cfg, user), nil)
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
		return nil, fmt.Errorf("woocommerce: list entitlements status %d: %s", status, string(body))
	}
	var resp struct {
		ID    json.Number `json:"id"`
		Email string      `json:"email"`
		Role  string      `json:"role"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("woocommerce: decode entitlements: %w", err)
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
