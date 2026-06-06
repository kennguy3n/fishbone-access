package sap_concur

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

// advanced-capability mapping for sap_concur:
//
//   - ProvisionAccess  -> POST   /api/v3.0/common/users
//     (Active=true + Roles list carrying resource_external_id)
//   - RevokeAccess     -> POST   /api/v3.0/common/users/{userID}/deactivate
//     (Concur soft-deactivates rather than hard-delete users)
//   - ListEntitlements -> GET    /api/v3.0/common/users/{userID}/roles
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Concur user ID or LoginID
//   - grant.ResourceExternalID -> role / permission slug
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func sapConcurValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("sap_concur: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("sap_concur: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *SAPConcurAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("sap_concur: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *SAPConcurAccessConnector) usersURL() string {
	return c.baseURL() + "/api/v3.0/common/users"
}

func (c *SAPConcurAccessConnector) userRolesURL(userID string) string {
	return c.usersURL() + "/" + url.PathEscape(strings.TrimSpace(userID)) + "/roles"
}

func (c *SAPConcurAccessConnector) deactivateURL(userID string) string {
	return c.usersURL() + "/" + url.PathEscape(strings.TrimSpace(userID)) + "/deactivate"
}

func (c *SAPConcurAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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

func (c *SAPConcurAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := sapConcurValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"LoginID": strings.TrimSpace(grant.UserExternalID),
		"Active":  true,
		"Roles":   []string{strings.TrimSpace(grant.ResourceExternalID)},
	})
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, c.usersURL(), payload)
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
		return fmt.Errorf("sap_concur: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("sap_concur: provision status %d: %s", status, string(body))
	}
}

func (c *SAPConcurAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := sapConcurValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost,
		c.deactivateURL(grant.UserExternalID), []byte(`{}`))
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
		return fmt.Errorf("sap_concur: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("sap_concur: revoke status %d: %s", status, string(body))
	}
}

func (c *SAPConcurAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("sap_concur: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, c.userRolesURL(user), nil)
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
		return nil, fmt.Errorf("sap_concur: list entitlements status %d: %s", status, string(body))
	}
	var envelope struct {
		Roles []struct {
			RoleID string `json:"RoleId"`
			Name   string `json:"Name"`
		} `json:"Roles"`
		Items []struct {
			RoleID string `json:"RoleId"`
			Name   string `json:"Name"`
		} `json:"Items"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("sap_concur: decode entitlements: %w", err)
	}
	raw := envelope.Roles
	if len(raw) == 0 {
		raw = envelope.Items
	}
	out := make([]access.Entitlement, 0, len(raw))
	for _, r := range raw {
		role := strings.TrimSpace(r.RoleID)
		if role == "" {
			role = strings.TrimSpace(r.Name)
		}
		if role == "" {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: role,
			Role:               role,
			Source:             "direct",
		})
	}
	return out, nil
}
