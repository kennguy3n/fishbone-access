package ovhcloud

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

// advanced-capability mapping for ovhcloud:
//
//   - ProvisionAccess  -> POST   /1.0/me/identity/user
//   - RevokeAccess     -> DELETE /1.0/me/identity/user/{login}
//   - ListEntitlements -> GET    /1.0/me/identity/user
//
// AccessGrant maps:
//   - grant.UserExternalID     -> OVHcloud sub-account login
//   - grant.ResourceExternalID -> role/group identifier
//
// OVH signature auth is reused from the existing connector.newRequest
// helper. Idempotent on (UserExternalID, ResourceExternalID).

func ovhValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("ovhcloud: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("ovhcloud: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *OVHcloudAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("ovhcloud: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *OVHcloudAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := ovhValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{
		"login":       strings.TrimSpace(grant.UserExternalID),
		"description": strings.TrimSpace(grant.ResourceExternalID),
		"group":       strings.TrimSpace(grant.ResourceExternalID),
	})
	endpoint := c.baseURL(cfg) + "/me/identity/user"
	req, err := c.newRequest(ctx, secrets, http.MethodPost, endpoint, string(payload))
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
		return fmt.Errorf("ovhcloud: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("ovhcloud: provision status %d: %s", status, string(body))
	}
}

func (c *OVHcloudAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := ovhValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	endpoint := c.baseURL(cfg) + "/me/identity/user/" + url.PathEscape(strings.TrimSpace(grant.UserExternalID))
	req, err := c.newRequest(ctx, secrets, http.MethodDelete, endpoint, "")
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
		return fmt.Errorf("ovhcloud: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("ovhcloud: revoke status %d: %s", status, string(body))
	}
}

func (c *OVHcloudAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("ovhcloud: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	endpoint := c.baseURL(cfg) + "/me/identity/user"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, endpoint, "")
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
		return nil, fmt.Errorf("ovhcloud: list entitlements status %d: %s", status, string(body))
	}
	// /1.0/me/identity/user returns a JSON array of login strings.
	var logins []string
	if err := json.Unmarshal(body, &logins); err != nil {
		return nil, fmt.Errorf("ovhcloud: decode entitlements: %w", err)
	}
	out := make([]access.Entitlement, 0)
	for _, login := range logins {
		if !strings.EqualFold(strings.TrimSpace(login), user) {
			continue
		}
		detailURL := endpoint + "/" + url.PathEscape(strings.TrimSpace(login))
		dreq, err := c.newRequest(ctx, secrets, http.MethodGet, detailURL, "")
		if err != nil {
			return nil, err
		}
		dStatus, dBody, dErr := c.doRaw(dreq)
		if dErr != nil {
			return nil, dErr
		}
		if dStatus < 200 || dStatus >= 300 {
			continue
		}
		var detail struct {
			Login string `json:"login"`
			Group string `json:"group"`
		}
		if jerr := json.Unmarshal(dBody, &detail); jerr != nil {
			continue
		}
		role := strings.TrimSpace(detail.Group)
		if role == "" {
			role = "member"
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: role,
			Role:               role,
			Source:             "direct",
		})
	}
	return out, nil
}
