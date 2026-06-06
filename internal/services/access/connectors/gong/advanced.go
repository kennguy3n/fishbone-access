package gong

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

// advanced-capability mapping for gong:
//
//   - ProvisionAccess  -> PUT    /v2/users/{user}/roles/{role}
//   - RevokeAccess     -> DELETE /v2/users/{user}/roles/{role}
//   - ListEntitlements -> GET    /v2/users/{user}/roles
//
// AccessGrant maps:
//   - grant.UserExternalID     -> gong user identifier
//   - grant.ResourceExternalID -> gong role identifier (round-trips in ListEntitlements)
//
// Idempotency is delegated to access.IsIdempotentProvisionStatus /
// access.IsIdempotentRevokeStatus per docs/architecture.md §2.

func gongValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("gong: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("gong: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *GongAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("gong: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *GongAccessConnector) grantURL(userExternalID, roleExternalID string) string {
	return fmt.Sprintf("%s/v2/users/%s/roles/%s",
		c.baseURL(),
		url.PathEscape(strings.TrimSpace(userExternalID)),
		url.PathEscape(strings.TrimSpace(roleExternalID)))
}

func (c *GongAccessConnector) entitlementsURL(userExternalID string) string {
	return fmt.Sprintf("%s/v2/users/%s/roles",
		c.baseURL(),
		url.PathEscape(strings.TrimSpace(userExternalID)))
}

func (c *GongAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := gongValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodPut, c.grantURL(grant.UserExternalID, grant.ResourceExternalID))
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
		return fmt.Errorf("gong: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("gong: provision status %d: %s", status, string(body))
	}
}

func (c *GongAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := gongValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodDelete, c.grantURL(grant.UserExternalID, grant.ResourceExternalID))
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
		return fmt.Errorf("gong: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("gong: revoke status %d: %s", status, string(body))
	}
}

func (c *GongAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("gong: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, c.entitlementsURL(user))
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
		return nil, fmt.Errorf("gong: list entitlements status %d: %s", status, string(body))
	}
	var envelope struct {
		Data []struct {
			ID   interface{} `json:"id"`
			Name string      `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		var bare []struct {
			ID   interface{} `json:"id"`
			Name string      `json:"name"`
		}
		if err2 := json.Unmarshal(body, &bare); err2 != nil {
			return nil, fmt.Errorf("gong: decode entitlements: %w", err)
		}
		envelope.Data = bare
	}
	out := make([]access.Entitlement, 0, len(envelope.Data))
	for _, r := range envelope.Data {
		id := strings.TrimSpace(fmt.Sprintf("%v", r.ID))
		if id == "" {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: id,
			Role:               strings.TrimSpace(r.Name),
			Source:             "direct",
		})
	}
	return out, nil
}
