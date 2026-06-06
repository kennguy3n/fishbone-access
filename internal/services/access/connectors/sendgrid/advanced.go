package sendgrid

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

// advanced-capability mapping for sendgrid:
//
//   - ProvisionAccess  -> POST   /v3/teammates                (invite teammate)
//   - RevokeAccess     -> DELETE /v3/teammates/{username}     (remove teammate)
//   - ListEntitlements -> GET    /v3/teammates/{username}     (scope -> entitlement)
//
// AccessGrant maps:
//   - grant.UserExternalID     -> SendGrid teammate username (or invite email)
//   - grant.ResourceExternalID -> scope slug (e.g. "mail.send", "marketing", "admin")
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func sendgridValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("sendgrid: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("sendgrid: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *SendgridAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("sendgrid: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *SendgridAccessConnector) teammatesURL() string {
	return c.baseURL() + "/v3/teammates"
}

func (c *SendgridAccessConnector) teammateURL(username string) string {
	return c.teammatesURL() + "/" + url.PathEscape(strings.TrimSpace(username))
}

func (c *SendgridAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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

func (c *SendgridAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := sendgridValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	scope := strings.TrimSpace(grant.ResourceExternalID)
	payload, _ := json.Marshal(map[string]interface{}{
		"email":    strings.TrimSpace(grant.UserExternalID),
		"scopes":   []string{scope},
		"is_admin": strings.EqualFold(scope, "admin"),
	})
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, c.teammatesURL(), payload)
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
		return fmt.Errorf("sendgrid: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("sendgrid: provision status %d: %s", status, string(body))
	}
}

func (c *SendgridAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := sendgridValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete, c.teammateURL(grant.UserExternalID), nil)
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
		return fmt.Errorf("sendgrid: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("sendgrid: revoke status %d: %s", status, string(body))
	}
}

func (c *SendgridAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("sendgrid: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, c.teammateURL(user), nil)
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
		return nil, fmt.Errorf("sendgrid: list entitlements status %d: %s", status, string(body))
	}
	var t struct {
		Username string   `json:"username"`
		Email    string   `json:"email"`
		Scopes   []string `json:"scopes"`
		IsAdmin  bool     `json:"is_admin"`
	}
	if err := json.Unmarshal(body, &t); err != nil {
		return nil, fmt.Errorf("sendgrid: decode entitlements: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(t.Username), user) &&
		!strings.EqualFold(strings.TrimSpace(t.Email), user) {
		return nil, nil
	}
	scopes := t.Scopes
	if t.IsAdmin {
		scopes = append([]string{"admin"}, scopes...)
	}
	out := make([]access.Entitlement, 0, len(scopes))
	for _, s := range scopes {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: s,
			Role:               s,
			Source:             "direct",
		})
	}
	return out, nil
}
