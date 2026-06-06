package recurly

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

// advanced-capability mapping for recurly:
//
//   - ProvisionAccess  -> POST   /accounts
//   - RevokeAccess     -> DELETE /accounts/{accountID}
//   - ListEntitlements -> GET    /accounts/{accountID}
//
// Recurly's public v3 API exposes the `accounts` resource (the same
// resource the connector's `Connect` probe and `SyncIdentities` already
// hit). It does NOT expose a top-level `/users` resource on this base
// URL, so the access-grant mapping uses accounts as the user identity
// space (`SyncIdentities` already projects Recurly accounts into
// `access.Identity`).
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Recurly account id (email)
//   - grant.ResourceExternalID -> role slug (admin|api|read_only|...)
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func recurlyValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("recurly: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("recurly: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *RecurlyAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("recurly: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *RecurlyAccessConnector) accountsURL() string { return c.baseURL() + "/accounts" }
func (c *RecurlyAccessConnector) accountURL(accountID string) string {
	return c.accountsURL() + "/" + url.PathEscape(strings.TrimSpace(accountID))
}

func (c *RecurlyAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *RecurlyAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := recurlyValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{
		"email": strings.TrimSpace(grant.UserExternalID),
		"role":  strings.TrimSpace(grant.ResourceExternalID),
	})
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, c.accountsURL(), payload)
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
		return fmt.Errorf("recurly: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("recurly: provision status %d: %s", status, string(body))
	}
}

func (c *RecurlyAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := recurlyValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete, c.accountURL(grant.UserExternalID), nil)
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
		return fmt.Errorf("recurly: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("recurly: revoke status %d: %s", status, string(body))
	}
}

func (c *RecurlyAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("recurly: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, c.accountURL(user), nil)
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
		return nil, fmt.Errorf("recurly: list entitlements status %d: %s", status, string(body))
	}
	var u struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := json.Unmarshal(body, &u); err != nil {
		return nil, fmt.Errorf("recurly: decode entitlements: %w", err)
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
