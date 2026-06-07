package ironclad

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

// advanced-capability mapping for ironclad:
//
//   - ProvisionAccess  -> PUT    /public/api/v1/users/{user}/groups/{role}
//   - RevokeAccess     -> DELETE /public/api/v1/users/{user}/groups/{role}
//   - ListEntitlements -> GET    /public/api/v1/users/{user}/groups
//
// AccessGrant maps:
//   - grant.UserExternalID     -> ironclad user identifier
//   - grant.ResourceExternalID -> ironclad group identifier (round-trips in ListEntitlements)
//
// Bearer auth via IroncladAccessConnector.newRequest. Idempotency is delegated to
// access.IsIdempotentProvisionStatus / access.IsIdempotentRevokeStatus
// per docs/architecture.md §2.

func ironcladValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("ironclad: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("ironclad: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *IroncladAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("ironclad: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *IroncladAccessConnector) grantURL(userExternalID, roleExternalID string) string {
	return fmt.Sprintf("%s/public/api/v1/users/%s/groups/%s",
		c.baseURL(),
		url.PathEscape(strings.TrimSpace(userExternalID)),
		url.PathEscape(strings.TrimSpace(roleExternalID)))
}

func (c *IroncladAccessConnector) listURL(userExternalID string) string {
	return fmt.Sprintf("%s/public/api/v1/users/%s/groups",
		c.baseURL(),
		url.PathEscape(strings.TrimSpace(userExternalID)))
}

func (c *IroncladAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := ironcladValidateGrant(grant); err != nil {
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
		return fmt.Errorf("ironclad: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("ironclad: provision status %d: %s", status, string(body))
	}
}

func (c *IroncladAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := ironcladValidateGrant(grant); err != nil {
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
		return fmt.Errorf("ironclad: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("ironclad: revoke status %d: %s", status, string(body))
	}
}

func (c *IroncladAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("ironclad: user external id is required")
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
		return nil, fmt.Errorf("ironclad: list entitlements status %d: %s", status, string(body))
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
			return nil, fmt.Errorf("ironclad: decode entitlements: %w", err)
		}
		envelope.Data = bare
	}
	out := make([]access.Entitlement, 0, len(envelope.Data))
	for _, r := range envelope.Data {
		id := strings.TrimSpace(fmt.Sprintf("%v", r.ID))
		// r.ID is interface{}, so a JSON null unmarshals to a Go nil and
		// fmt.Sprintf("%v", nil) yields the literal "<nil>" — guard it
		// alongside the empty case so a null id never leaks through as a
		// bogus ResourceExternalID (matches insightly/advanced.go).
		if id == "" || id == "<nil>" {
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
