package pandadoc

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

// advanced-capability mapping for pandadoc:
//
//   - ProvisionAccess  -> PUT    /public/v1/members/{user}/roles/{role}
//   - RevokeAccess     -> DELETE /public/v1/members/{user}/roles/{role}
//   - ListEntitlements -> GET    /public/v1/members/{user}/roles
//
// AccessGrant maps:
//   - grant.UserExternalID     -> pandadoc user identifier
//   - grant.ResourceExternalID -> pandadoc role identifier (round-trips in ListEntitlements)
//
// Bearer auth via PandaDocAccessConnector.newRequest. Idempotency is delegated to
// access.IsIdempotentProvisionStatus / access.IsIdempotentRevokeStatus
// per docs/architecture.md §2.

func pandadocValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("pandadoc: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("pandadoc: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *PandaDocAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.doHTTP(req)
	if err != nil {
		return 0, nil, fmt.Errorf("pandadoc: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *PandaDocAccessConnector) grantURL(userExternalID, roleExternalID string) string {
	return fmt.Sprintf("%s/public/v1/members/%s/roles/%s",
		c.baseURL(),
		url.PathEscape(strings.TrimSpace(userExternalID)),
		url.PathEscape(strings.TrimSpace(roleExternalID)))
}

func (c *PandaDocAccessConnector) listURL(userExternalID string) string {
	return fmt.Sprintf("%s/public/v1/members/%s/roles",
		c.baseURL(),
		url.PathEscape(strings.TrimSpace(userExternalID)))
}

func (c *PandaDocAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := pandadocValidateGrant(grant); err != nil {
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
		return fmt.Errorf("pandadoc: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("pandadoc: provision status %d: %s", status, string(body))
	}
}

func (c *PandaDocAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := pandadocValidateGrant(grant); err != nil {
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
		return fmt.Errorf("pandadoc: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("pandadoc: revoke status %d: %s", status, string(body))
	}
}

func (c *PandaDocAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("pandadoc: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, c.listURL(user))
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
		return nil, fmt.Errorf("pandadoc: list entitlements status %d: %s", status, string(body))
	}
	var envelope struct {
		Data []struct {
			ID   interface{} `json:"id"`
			Name string      `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		// Some providers omit the envelope and return a bare array.
		var bare []struct {
			ID   interface{} `json:"id"`
			Name string      `json:"name"`
		}
		if err2 := json.Unmarshal(body, &bare); err2 != nil {
			return nil, fmt.Errorf("pandadoc: decode entitlements: %w", err)
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
