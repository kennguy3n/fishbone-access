package gorgias

import (
	"bytes"
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

// advanced-capability mapping for Gorgias:
//
//   - ProvisionAccess  -> POST   /api/users    body {email, role}
//   - RevokeAccess     -> DELETE /api/users/{user_id}
//   - ListEntitlements -> GET    /api/users?email={email}  (filtered)
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Gorgias user email (preferred) or numeric id
//   - grant.ResourceExternalID -> Gorgias role (agent / admin / lead / observer)
//
// HTTP Basic email:api_key auth via gorgias.newRequest.

const gorgiasDefaultRole = "agent"

func gorgiasValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("gorgias: grant.UserExternalID is required")
	}
	return nil
}

// gorgiasRole resolves the role to assign. Gorgias has no separate
// resource to grant against — a user's single workspace role *is* the
// entitlement — so ResourceExternalID carries the role here (see the
// AccessGrant mapping above). This deliberately differs from the other
// connectors, where ResourceExternalID identifies a resource (group /
// team / job). Precedence: explicit Role, then ResourceExternalID, then
// the default "agent".
func gorgiasRole(g access.AccessGrant) string {
	if r := strings.TrimSpace(g.Role); r != "" {
		return r
	}
	if r := strings.TrimSpace(g.ResourceExternalID); r != "" {
		return r
	}
	return gorgiasDefaultRole
}

func (c *GorgiasAccessConnector) newRequestWithBody(ctx context.Context, cfg Config, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Gorgias-Account", strings.TrimSpace(cfg.Account))
	creds := strings.TrimSpace(secrets.Email) + ":" + strings.TrimSpace(secrets.APIKey)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	return req, nil
}

func (c *GorgiasAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("gorgias: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *GorgiasAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := gorgiasValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"email": strings.TrimSpace(grant.UserExternalID),
		"role":  gorgiasRole(grant),
	})
	endpoint := c.baseURL(cfg) + "/api/users"
	req, err := c.newRequestWithBody(ctx, cfg, secrets, http.MethodPost, endpoint, payload)
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
		return fmt.Errorf("gorgias: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("gorgias: provision status %d: %s", status, string(body))
	}
}

func (c *GorgiasAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := gorgiasValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	id, err := c.findGorgiasUserID(ctx, cfg, secrets, grant.UserExternalID)
	if err != nil {
		return err
	}
	if id == "" {
		return nil
	}
	endpoint := fmt.Sprintf("%s/api/users/%s", c.baseURL(cfg), url.PathEscape(id))
	req, err := c.newRequestWithBody(ctx, cfg, secrets, http.MethodDelete, endpoint, nil)
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
		return fmt.Errorf("gorgias: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("gorgias: revoke status %d: %s", status, string(body))
	}
}

func (c *GorgiasAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("gorgias: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	matches, err := c.listGorgiasUsersByEmail(ctx, cfg, secrets, user)
	if err != nil {
		return nil, err
	}
	// Gorgias users can have at most one role per workspace, so
	// any non-empty match is the authoritative entitlement.
	if len(matches) == 0 {
		return nil, nil
	}
	role := strings.TrimSpace(matches[0].Role)
	if role == "" {
		role = gorgiasDefaultRole
	}
	return []access.Entitlement{{
		ResourceExternalID: role,
		Role:               role,
		Source:             "direct",
	}}, nil
}

func (c *GorgiasAccessConnector) findGorgiasUserID(ctx context.Context, cfg Config, secrets Secrets, identifier string) (string, error) {
	matches, err := c.listGorgiasUsersByEmail(ctx, cfg, secrets, identifier)
	if err != nil {
		return "", err
	}
	for i := range matches {
		return fmt.Sprintf("%d", matches[i].ID), nil
	}
	return "", nil
}

func (c *GorgiasAccessConnector) listGorgiasUsersByEmail(ctx context.Context, cfg Config, secrets Secrets, email string) ([]gorgiasUser, error) {
	q := url.Values{}
	q.Set("email", strings.TrimSpace(email))
	endpoint := fmt.Sprintf("%s/api/users?%s", c.baseURL(cfg), q.Encode())
	req, err := c.newRequest(ctx, cfg, secrets, http.MethodGet, endpoint)
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
		return nil, fmt.Errorf("gorgias: list users status %d: %s", status, string(body))
	}
	var resp gorgiasListResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("gorgias: decode users: %w", err)
	}
	out := make([]gorgiasUser, 0, len(resp.Data))
	for i := range resp.Data {
		if strings.EqualFold(strings.TrimSpace(resp.Data[i].Email), strings.TrimSpace(email)) {
			out = append(out, resp.Data[i])
		}
	}
	return out, nil
}
