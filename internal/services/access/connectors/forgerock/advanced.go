package forgerock

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

// advanced-capability mapping for ForgeRock IDM /openidm/managed/user:
//
//   - ProvisionAccess  -> PUT    /openidm/managed/user/{id}
//   - RevokeAccess     -> DELETE /openidm/managed/user/{id}
//   - ListEntitlements -> GET    /openidm/managed/user/{id}
//
// CREST PUT is used for create-or-replace; If-None-Match: * would make it
// strictly create-only but we keep PUT idempotent so re-running ProvisionAccess
// converges. Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func forgerockValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("forgerock: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("forgerock: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *ForgeRockAccessConnector) userURL(cfg Config, id string) string {
	return c.baseURL(cfg) + "/openidm/managed/user/" + url.PathEscape(strings.TrimSpace(id))
}

func (c *ForgeRockAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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

func (c *ForgeRockAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("forgerock: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *ForgeRockAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := forgerockValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"userName": strings.TrimSpace(grant.UserExternalID),
		"role":     strings.TrimSpace(grant.ResourceExternalID),
	})
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPut, c.userURL(cfg, grant.UserExternalID), payload)
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
		return fmt.Errorf("forgerock: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("forgerock: provision status %d: %s", status, string(body))
	}
}

func (c *ForgeRockAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := forgerockValidateGrant(grant); err != nil {
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
		return fmt.Errorf("forgerock: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("forgerock: revoke status %d: %s", status, string(body))
	}
}

func (c *ForgeRockAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("forgerock: user external id is required")
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
		return nil, fmt.Errorf("forgerock: list entitlements status %d: %s", status, string(body))
	}
	var resp struct {
		UserName string `json:"userName"`
		ID       string `json:"_id"`
		Role     string `json:"role"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("forgerock: decode entitlements: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(resp.UserName), user) &&
		strings.TrimSpace(resp.ID) != user {
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
