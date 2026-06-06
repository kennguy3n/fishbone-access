package twilio

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

// advanced-capability mapping for twilio:
//
//   - ProvisionAccess  -> POST   /2010-04-01/Accounts/{sid}/Users.json
//   - RevokeAccess     -> DELETE /2010-04-01/Accounts/{sid}/Users/{user_sid}.json
//   - ListEntitlements -> GET    /2010-04-01/Accounts/{sid}/Users/{user_sid}.json
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Twilio user SID (or friendly identity)
//   - grant.ResourceExternalID -> role slug ("admin", "developer", "support", ...)
//
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func twilioValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("twilio: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("twilio: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *TwilioAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("twilio: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *TwilioAccessConnector) userURL(secrets Secrets, userSID string) string {
	return c.baseURL() + "/2010-04-01/Accounts/" + url.PathEscape(strings.TrimSpace(secrets.AccountSID)) +
		"/Users/" + url.PathEscape(strings.TrimSpace(userSID)) + ".json"
}

func (c *TwilioAccessConnector) newFormRequest(ctx context.Context, secrets Secrets, method, fullURL string, form url.Values) (*http.Request, error) {
	var rdr io.Reader
	if form != nil {
		rdr = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.SetBasicAuth(strings.TrimSpace(secrets.AccountSID), strings.TrimSpace(secrets.AuthToken))
	return req, nil
}

func (c *TwilioAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := twilioValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	form := url.Values{
		"Identity": []string{strings.TrimSpace(grant.UserExternalID)},
		"Role":     []string{strings.TrimSpace(grant.ResourceExternalID)},
	}
	req, err := c.newFormRequest(ctx, secrets, http.MethodPost,
		c.baseURL()+c.usersPath(secrets), form)
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
		return fmt.Errorf("twilio: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("twilio: provision status %d: %s", status, string(body))
	}
}

func (c *TwilioAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := twilioValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newFormRequest(ctx, secrets, http.MethodDelete, c.userURL(secrets, grant.UserExternalID), nil)
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
		return fmt.Errorf("twilio: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("twilio: revoke status %d: %s", status, string(body))
	}
}

func (c *TwilioAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("twilio: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newFormRequest(ctx, secrets, http.MethodGet, c.userURL(secrets, user), nil)
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
		return nil, fmt.Errorf("twilio: list entitlements status %d: %s", status, string(body))
	}
	var m struct {
		SID      string `json:"sid"`
		Identity string `json:"identity"`
		Role     string `json:"role"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("twilio: decode entitlements: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(m.SID), user) &&
		!strings.EqualFold(strings.TrimSpace(m.Identity), user) {
		return nil, nil
	}
	role := strings.TrimSpace(m.Role)
	if role == "" {
		return []access.Entitlement{}, nil
	}
	return []access.Entitlement{{
		ResourceExternalID: role,
		Role:               role,
		Source:             "direct",
	}}, nil
}
