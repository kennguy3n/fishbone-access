package heroku

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

// advanced-capability mapping for heroku:
//
//   - ProvisionAccess  -> PUT    /teams/{team}/members
//     (with body {email, role})
//   - RevokeAccess     -> DELETE /teams/{team}/members/{email}
//   - ListEntitlements -> GET    /teams/{team}/members
//
// AccessGrant maps:
//   - grant.UserExternalID     -> heroku user email
//   - grant.ResourceExternalID -> team role (member|admin|owner|collaborator)
//
// The team is read from connector Config.TeamName so the same connector
// instance always operates against the same team. Idempotent on
// (UserExternalID, ResourceExternalID) per docs/architecture.md §2: Heroku
// returns 422 "already" for double-PUTs and 404 for double-DELETEs.

func herokuValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("heroku: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("heroku: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *HerokuAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("heroku: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *HerokuAccessConnector) teamMembersURL(team string) string {
	return c.baseURL() + "/teams/" + url.PathEscape(strings.TrimSpace(team)) + "/members"
}

func (c *HerokuAccessConnector) teamMemberURL(team, email string) string {
	return c.baseURL() + "/teams/" + url.PathEscape(strings.TrimSpace(team)) + "/members/" + url.PathEscape(strings.TrimSpace(email))
}

func (c *HerokuAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	var rdr io.Reader
	if len(body) > 0 {
		rdr = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.heroku+json; version=3")
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.APIKey))
	return req, nil
}

func (c *HerokuAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := herokuValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	if strings.TrimSpace(cfg.TeamName) == "" {
		return errors.New("heroku: team_name is required for ProvisionAccess")
	}
	payload, _ := json.Marshal(map[string]string{
		"email": strings.TrimSpace(grant.UserExternalID),
		"role":  strings.TrimSpace(grant.ResourceExternalID),
	})
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPut,
		c.teamMembersURL(cfg.TeamName), payload)
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
		return fmt.Errorf("heroku: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("heroku: provision status %d: %s", status, string(body))
	}
}

func (c *HerokuAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := herokuValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	if strings.TrimSpace(cfg.TeamName) == "" {
		return errors.New("heroku: team_name is required for RevokeAccess")
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete,
		c.teamMemberURL(cfg.TeamName, grant.UserExternalID), nil)
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
		return fmt.Errorf("heroku: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("heroku: revoke status %d: %s", status, string(body))
	}
}

func (c *HerokuAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("heroku: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.TeamName) == "" {
		return nil, nil
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet,
		c.teamMembersURL(cfg.TeamName), nil)
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
		return nil, fmt.Errorf("heroku: list entitlements status %d: %s", status, string(body))
	}
	var members []struct {
		Email string `json:"email"`
		Role  string `json:"role"`
		User  struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"user"`
	}
	if err := json.Unmarshal(body, &members); err != nil {
		return nil, fmt.Errorf("heroku: decode entitlements: %w", err)
	}
	out := make([]access.Entitlement, 0, len(members))
	for _, m := range members {
		if !strings.EqualFold(m.Email, user) && !strings.EqualFold(m.User.Email, user) && m.User.ID != user {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: strings.TrimSpace(m.Role),
			Role:               strings.TrimSpace(m.Role),
			Source:             "direct",
		})
	}
	return out, nil
}
