package namely

import (
	"bytes"
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

// advanced-capability mapping for Namely:
//
//   - ProvisionAccess  -> POST   /api/v1/profiles/{id}/groups   body {"group_id":"..."}
//   - RevokeAccess     -> DELETE /api/v1/profiles/{id}/groups/{group_id}
//   - ListEntitlements -> GET    /api/v1/profiles/{id}/groups
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Namely profile id
//   - grant.ResourceExternalID -> Namely group id
//
// Bearer auth via NamelyAccessConnector.newRequest.

func namelyValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("namely: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("namely: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *NamelyAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("namely: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *NamelyAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := namelyValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/api/v1/profiles/%s/groups",
		c.baseURL(cfg),
		url.PathEscape(strings.TrimSpace(grant.UserExternalID)))
	body, _ := json.Marshal(map[string]string{"group_id": strings.TrimSpace(grant.ResourceExternalID)})
	req, err := c.newRequest(ctx, secrets, http.MethodPost, endpoint)
	if err != nil {
		return err
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/json")
	status, respBody, err := c.doRaw(req)
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case access.IsIdempotentProvisionStatus(status, respBody):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("namely: provision transient status %d: %s", status, string(respBody))
	default:
		return fmt.Errorf("namely: provision status %d: %s", status, string(respBody))
	}
}

func (c *NamelyAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := namelyValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/api/v1/profiles/%s/groups/%s",
		c.baseURL(cfg),
		url.PathEscape(strings.TrimSpace(grant.UserExternalID)),
		url.PathEscape(strings.TrimSpace(grant.ResourceExternalID)))
	req, err := c.newRequest(ctx, secrets, http.MethodDelete, endpoint)
	if err != nil {
		return err
	}
	status, respBody, err := c.doRaw(req)
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case access.IsIdempotentRevokeStatus(status, respBody):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("namely: revoke transient status %d: %s", status, string(respBody))
	default:
		return fmt.Errorf("namely: revoke status %d: %s", status, string(respBody))
	}
}

func (c *NamelyAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("namely: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/api/v1/profiles/%s/groups",
		c.baseURL(cfg),
		url.PathEscape(user))
	req, err := c.newRequest(ctx, secrets, http.MethodGet, endpoint)
	if err != nil {
		return nil, err
	}
	status, respBody, err := c.doRaw(req)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("namely: list groups status %d: %s", status, string(respBody))
	}
	var envelope struct {
		Groups []struct {
			ID   interface{} `json:"id"`
			Name string      `json:"name"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(respBody, &envelope); err != nil {
		return nil, fmt.Errorf("namely: decode groups: %w", err)
	}
	out := make([]access.Entitlement, 0, len(envelope.Groups))
	for _, g := range envelope.Groups {
		id := strings.TrimSpace(fmt.Sprintf("%v", g.ID))
		if id == "" {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: id,
			Role:               strings.TrimSpace(g.Name),
			Source:             "direct",
		})
	}
	return out, nil
}
