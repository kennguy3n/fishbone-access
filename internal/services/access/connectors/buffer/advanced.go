package buffer

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

// advanced-capability mapping for Buffer:
//
//   - ProvisionAccess  -> POST   /1/profiles.json              (add profile to team)
//   - RevokeAccess     -> DELETE /1/profiles/{id}.json         (remove profile)
//   - ListEntitlements -> GET    /1/profiles/{id}.json         (current profile + service)
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Buffer profile id or service handle
//   - grant.ResourceExternalID -> service slug (e.g. "twitter", "facebook", "linkedin")
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func bufferValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("buffer: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("buffer: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *BufferAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("buffer: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *BufferAccessConnector) profilesURL() string {
	return c.baseURL() + "/1/profiles.json"
}

func (c *BufferAccessConnector) profileURL(profileID string) string {
	return c.baseURL() + "/1/profiles/" + url.PathEscape(strings.TrimSpace(profileID)) + ".json"
}

func (c *BufferAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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

func (c *BufferAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := bufferValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"service":         strings.TrimSpace(grant.ResourceExternalID),
		"service_id":      strings.TrimSpace(grant.UserExternalID),
		"service_user_id": strings.TrimSpace(grant.UserExternalID),
	})
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, c.profilesURL(), payload)
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
		return fmt.Errorf("buffer: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("buffer: provision status %d: %s", status, string(body))
	}
}

func (c *BufferAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := bufferValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete, c.profileURL(grant.UserExternalID), nil)
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
		return fmt.Errorf("buffer: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("buffer: revoke status %d: %s", status, string(body))
	}
}

func (c *BufferAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("buffer: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, c.profileURL(user), nil)
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
		return nil, fmt.Errorf("buffer: list entitlements status %d: %s", status, string(body))
	}
	var resp struct {
		ID      string `json:"id"`
		Service string `json:"service"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("buffer: decode entitlements: %w", err)
	}
	if strings.TrimSpace(resp.ID) != user {
		return nil, nil
	}
	service := strings.TrimSpace(resp.Service)
	if service == "" {
		return []access.Entitlement{}, nil
	}
	return []access.Entitlement{{
		ResourceExternalID: service,
		Role:               service,
		Source:             "direct",
	}}, nil
}
