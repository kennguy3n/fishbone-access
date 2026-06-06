package activecampaign

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

// advanced-capability mapping for activecampaign:
//
//   - ProvisionAccess  -> POST   /api/3/userGroups
//                         body {userGroup: {user, userGroup}}
//   - RevokeAccess     -> DELETE /api/3/userGroups/{id}
//                         (after a lookup by user_id+userGroup_id)
//   - ListEntitlements -> GET    /api/3/users/{user_id}/userGroups
//
// AccessGrant maps:
//   - grant.UserExternalID     -> AC user id
//   - grant.ResourceExternalID -> AC userGroup id
//
// Auth uses the Api-Token header (already set by newRequest).
// Idempotent on (UserExternalID, ResourceExternalID) per docs/architecture.md §2.

func acValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("activecampaign: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("activecampaign: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *ActiveCampaignAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("activecampaign: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *ActiveCampaignAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
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
	req.Header.Set("Api-Token", strings.TrimSpace(secrets.APIKey))
	return req, nil
}

type acUserGroupRecord struct {
	ID        string `json:"id"`
	User      string `json:"user"`
	UserGroup string `json:"userGroup"`
}

type acUserGroupResponse struct {
	UserGroups []acUserGroupRecord `json:"userGroups"`
}

func (c *ActiveCampaignAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := acValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"userGroup": map[string]string{
			"user":      strings.TrimSpace(grant.UserExternalID),
			"userGroup": strings.TrimSpace(grant.ResourceExternalID),
		},
	})
	endpoint := c.baseURL(cfg) + "/api/3/userGroups"
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, endpoint, payload)
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
		return fmt.Errorf("activecampaign: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("activecampaign: provision status %d: %s", status, string(body))
	}
}

func (c *ActiveCampaignAccessConnector) lookupUserGroupID(ctx context.Context, cfg Config, secrets Secrets, userID, groupID string) (string, error) {
	q := url.Values{
		"filters[user]":      []string{userID},
		"filters[userGroup]": []string{groupID},
		"limit":              []string{"1"},
	}
	endpoint := c.baseURL(cfg) + "/api/3/userGroups?" + q.Encode()
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	status, body, err := c.doRaw(req)
	if err != nil {
		return "", err
	}
	if status == http.StatusNotFound {
		return "", nil
	}
	if status < 200 || status >= 300 {
		return "", fmt.Errorf("activecampaign: lookup userGroup status %d: %s", status, string(body))
	}
	var resp acUserGroupResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("activecampaign: decode userGroups: %w", err)
	}
	for _, r := range resp.UserGroups {
		if strings.EqualFold(r.User, userID) && strings.EqualFold(r.UserGroup, groupID) {
			return r.ID, nil
		}
	}
	return "", nil
}

func (c *ActiveCampaignAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := acValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	id, err := c.lookupUserGroupID(ctx, cfg, secrets,
		strings.TrimSpace(grant.UserExternalID), strings.TrimSpace(grant.ResourceExternalID))
	if err != nil {
		return err
	}
	if id == "" {
		return nil
	}
	endpoint := c.baseURL(cfg) + "/api/3/userGroups/" + url.PathEscape(id)
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete, endpoint, nil)
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
		return fmt.Errorf("activecampaign: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("activecampaign: revoke status %d: %s", status, string(body))
	}
}

func (c *ActiveCampaignAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("activecampaign: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	q := url.Values{
		"filters[user]": []string{user},
		"limit":         []string{"100"},
	}
	endpoint := c.baseURL(cfg) + "/api/3/userGroups?" + q.Encode()
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, endpoint, nil)
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
		return nil, fmt.Errorf("activecampaign: list entitlements status %d: %s", status, string(body))
	}
	var resp acUserGroupResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("activecampaign: decode userGroups: %w", err)
	}
	out := make([]access.Entitlement, 0, len(resp.UserGroups))
	for _, r := range resp.UserGroups {
		if !strings.EqualFold(strings.TrimSpace(r.User), user) {
			continue
		}
		group := strings.TrimSpace(r.UserGroup)
		if group == "" {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: group,
			Role:               group,
			Source:             "direct",
		})
	}
	return out, nil
}
