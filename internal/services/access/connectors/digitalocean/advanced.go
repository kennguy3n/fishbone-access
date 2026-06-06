package digitalocean

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

// advanced-capability mapping for digitalocean:
//
//   - ProvisionAccess  -> POST   /v2/teams/{team_id}/members
//   - RevokeAccess     -> DELETE /v2/teams/{team_id}/members/{user_id}
//   - ListEntitlements -> GET    /v2/teams/{team_id}/members
//
// AccessGrant maps:
//   - grant.UserExternalID     -> DO user identifier (email/uuid)
//   - grant.ResourceExternalID -> DO team identifier
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func doValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("digitalocean: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("digitalocean: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *DigitalOceanAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("digitalocean: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *DigitalOceanAccessConnector) teamMembersURL(team string) string {
	return c.baseURL() + "/v2/teams/" + url.PathEscape(strings.TrimSpace(team)) + "/members"
}

func (c *DigitalOceanAccessConnector) teamMemberURL(team, user string) string {
	return c.baseURL() + "/v2/teams/" + url.PathEscape(strings.TrimSpace(team)) + "/members/" + url.PathEscape(strings.TrimSpace(user))
}

func (c *DigitalOceanAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.APIToken))
	return req, nil
}

func (c *DigitalOceanAccessConnector) ProvisionAccess(ctx context.Context, _, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := doValidateGrant(grant); err != nil {
		return err
	}
	secrets, err := c.decodeBoth(secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{"email": strings.TrimSpace(grant.UserExternalID)})
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost,
		c.teamMembersURL(grant.ResourceExternalID), payload)
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
		return fmt.Errorf("digitalocean: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("digitalocean: provision status %d: %s", status, string(body))
	}
}

func (c *DigitalOceanAccessConnector) RevokeAccess(ctx context.Context, _, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := doValidateGrant(grant); err != nil {
		return err
	}
	secrets, err := c.decodeBoth(secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete,
		c.teamMemberURL(grant.ResourceExternalID, grant.UserExternalID), nil)
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
		return fmt.Errorf("digitalocean: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("digitalocean: revoke status %d: %s", status, string(body))
	}
}

func (c *DigitalOceanAccessConnector) ListEntitlements(ctx context.Context, _, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("digitalocean: user external id is required")
	}
	secrets, err := c.decodeBoth(secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, c.baseURL()+"/v2/teams", nil)
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
		return nil, fmt.Errorf("digitalocean: list entitlements status %d: %s", status, string(body))
	}
	var envelope struct {
		Teams []struct {
			ID      string `json:"id"`
			Members []struct {
				Email string `json:"email"`
				UUID  string `json:"uuid"`
			} `json:"members"`
		} `json:"teams"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("digitalocean: decode entitlements: %w", err)
	}
	out := make([]access.Entitlement, 0, len(envelope.Teams))
	for _, t := range envelope.Teams {
		for _, m := range t.Members {
			if strings.EqualFold(m.Email, user) || m.UUID == user {
				out = append(out, access.Entitlement{
					ResourceExternalID: strings.TrimSpace(t.ID),
					Role:               "member",
					Source:             "direct",
				})
				break
			}
		}
	}
	return out, nil
}
