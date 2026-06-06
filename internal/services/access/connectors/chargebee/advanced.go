package chargebee

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

// advanced-capability mapping for chargebee:
//
//   - ProvisionAccess  -> POST   /api/v2/customers
//   - RevokeAccess     -> DELETE /api/v2/customers/{customerID}
//   - ListEntitlements -> GET    /api/v2/customers/{customerID}
//
// Chargebee's public v2 API exposes the `customers` resource (the same
// resource the connector's `Connect` probe and `SyncIdentities` already
// hit). It does NOT expose a top-level `/api/v2/users` admin-user
// resource, so the access-grant mapping uses customers as the user
// identity space (`SyncIdentities` already projects Chargebee customers
// into `access.Identity`).
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Chargebee customer id (email)
//   - grant.ResourceExternalID -> role slug (admin|read_only|...)
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func chargebeeValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("chargebee: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("chargebee: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *ChargebeeAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("chargebee: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *ChargebeeAccessConnector) customersURL(cfg Config) string {
	return c.baseURL(cfg) + "/api/v2/customers"
}

func (c *ChargebeeAccessConnector) customerURL(cfg Config, customerID string) string {
	return c.customersURL(cfg) + "/" + url.PathEscape(strings.TrimSpace(customerID))
}

func (c *ChargebeeAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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
	creds := strings.TrimSpace(secrets.APIKey) + ":"
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	return req, nil
}

// newFormRequest builds a write request whose parameters are sent as
// application/x-www-form-urlencoded. Chargebee's v2 API accepts request
// parameters as form-encoded data (its own curl docs use `-d key=value`),
// NOT a JSON body — posting application/json silently drops every field,
// so the customer would be created without the intended attributes.
func (c *ChargebeeAccessConnector) newFormRequest(ctx context.Context, secrets Secrets, method, fullURL string, form url.Values) (*http.Request, error) {
	encoded := form.Encode()
	var rdr io.Reader
	if encoded != "" {
		rdr = strings.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if encoded != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	creds := strings.TrimSpace(secrets.APIKey) + ":"
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	return req, nil
}

func (c *ChargebeeAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := chargebeeValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	form := url.Values{}
	form.Set("email", strings.TrimSpace(grant.UserExternalID))
	form.Set("role", strings.TrimSpace(grant.ResourceExternalID))
	req, err := c.newFormRequest(ctx, secrets, http.MethodPost, c.customersURL(cfg), form)
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
		return fmt.Errorf("chargebee: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("chargebee: provision status %d: %s", status, string(body))
	}
}

func (c *ChargebeeAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := chargebeeValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete, c.customerURL(cfg, grant.UserExternalID), nil)
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
		return fmt.Errorf("chargebee: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("chargebee: revoke status %d: %s", status, string(body))
	}
}

func (c *ChargebeeAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("chargebee: user external id is required")
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
		return nil, fmt.Errorf("chargebee: list entitlements status %d: %s", status, string(body))
	}
	var u struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := json.Unmarshal(body, &u); err != nil {
		return nil, fmt.Errorf("chargebee: decode entitlements: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(u.Email), user) && strings.TrimSpace(u.ID) != user {
		return nil, nil
	}
	role := strings.TrimSpace(u.Role)
	if role == "" {
		return []access.Entitlement{}, nil
	}
	return []access.Entitlement{{
		ResourceExternalID: role,
		Role:               role,
		Source:             "direct",
	}}, nil
}
