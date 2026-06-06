package jotform

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

// advanced-capability mapping for Jotform:
//
//   - ProvisionAccess  -> POST   /user/sub-users           (create sub-user)
//   - RevokeAccess     -> DELETE /user/sub-users/{id}      (remove sub-user)
//   - ListEntitlements -> GET    /user/sub-users/{id}      (current sub-user + role)
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Jotform sub-user id or email
//   - grant.ResourceExternalID -> permission slug ("admin", "editor", "viewer")
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func jotformValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("jotform: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("jotform: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *JotformAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("jotform: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *JotformAccessConnector) subUsersURL() string {
	return c.baseURL() + "/user/sub-users"
}

func (c *JotformAccessConnector) subUserURL(userID string) string {
	return c.baseURL() + "/user/sub-users/" + url.PathEscape(strings.TrimSpace(userID))
}

func (c *JotformAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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
	tok := strings.TrimSpace(secrets.Token)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("APIKEY", tok)
	return req, nil
}

func (c *JotformAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := jotformValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"email":      strings.TrimSpace(grant.UserExternalID),
		"permission": strings.TrimSpace(grant.ResourceExternalID),
	})
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, c.subUsersURL(), payload)
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
		return fmt.Errorf("jotform: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("jotform: provision status %d: %s", status, string(body))
	}
}

func (c *JotformAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := jotformValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete, c.subUserURL(grant.UserExternalID), nil)
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
		return fmt.Errorf("jotform: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("jotform: revoke status %d: %s", status, string(body))
	}
}

func (c *JotformAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("jotform: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, c.subUserURL(user), nil)
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
		return nil, fmt.Errorf("jotform: list entitlements status %d: %s", status, string(body))
	}
	var resp struct {
		Content struct {
			ID         string `json:"id"`
			Email      string `json:"email"`
			Permission string `json:"permission"`
		} `json:"content"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("jotform: decode entitlements: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(resp.Content.Email), user) &&
		strings.TrimSpace(resp.Content.ID) != user {
		return nil, nil
	}
	role := strings.TrimSpace(resp.Content.Permission)
	if role == "" {
		return []access.Entitlement{}, nil
	}
	return []access.Entitlement{{
		ResourceExternalID: role,
		Role:               role,
		Source:             "direct",
	}}, nil
}
