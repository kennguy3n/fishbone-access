package knowbe4

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// advanced-capability mapping for KnowBe4:
//
//   - ProvisionAccess  -> POST   /v1/groups/{group_id}/members
//                         body { user_id }
//   - RevokeAccess     -> DELETE /v1/groups/{group_id}/members/{user_id}
//   - ListEntitlements -> GET    /v1/groups/{group_id}/members
//
// AccessGrant maps:
//   - grant.UserExternalID     -> KnowBe4 user id (numeric)
//   - grant.ResourceExternalID -> KnowBe4 group id (numeric)
//
// Bearer auth via KnowBe4AccessConnector.newRequest. Region (us/eu/ca)
// is taken from cfg.Region per the baseURL routing rules.

func knowbe4ValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("knowbe4: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("knowbe4: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *KnowBe4AccessConnector) newRequestWithBody(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *KnowBe4AccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("knowbe4: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *KnowBe4AccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := knowbe4ValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	// KnowBe4 represents user IDs as JSON numbers everywhere (the member
	// list, audit feed, and SyncIdentities all use numeric ids), so send
	// user_id as a number to match the API's data model. ExternalID is the
	// stringified numeric id; fall back to the raw string only if it is not
	// numeric so a non-standard id is still forwarded rather than dropped.
	userID := strings.TrimSpace(grant.UserExternalID)
	payloadMap := map[string]interface{}{"user_id": userID}
	if n, convErr := strconv.ParseInt(userID, 10, 64); convErr == nil {
		payloadMap["user_id"] = n
	}
	payload, _ := json.Marshal(payloadMap)
	endpoint := fmt.Sprintf("%s/v1/groups/%s/members",
		c.baseURL(cfg),
		url.PathEscape(strings.TrimSpace(grant.ResourceExternalID)))
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodPost, endpoint, payload)
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
		return fmt.Errorf("knowbe4: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("knowbe4: provision status %d: %s", status, string(body))
	}
}

func (c *KnowBe4AccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := knowbe4ValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/v1/groups/%s/members/%s",
		c.baseURL(cfg),
		url.PathEscape(strings.TrimSpace(grant.ResourceExternalID)),
		url.PathEscape(strings.TrimSpace(grant.UserExternalID)))
	req, err := c.newRequestWithBody(ctx, secrets, http.MethodDelete, endpoint, nil)
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
		return fmt.Errorf("knowbe4: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("knowbe4: revoke status %d: %s", status, string(body))
	}
}

func (c *KnowBe4AccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("knowbe4: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	groupID := knowbe4OptionalGroupID(configRaw)
	if groupID == "" {
		return nil, errors.New("knowbe4: group_id is required in config for ListEntitlements")
	}
	endpoint := fmt.Sprintf("%s/v1/groups/%s/members",
		c.baseURL(cfg), url.PathEscape(groupID))
	req, err := c.newRequest(ctx, secrets, http.MethodGet, endpoint)
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
		return nil, fmt.Errorf("knowbe4: list group members status %d: %s", status, string(body))
	}
	var members []struct {
		ID    json.Number `json:"id"`
		Email string      `json:"email"`
	}
	if err := json.Unmarshal(body, &members); err != nil {
		return nil, fmt.Errorf("knowbe4: decode members: %w", err)
	}
	for i := range members {
		idStr := members[i].ID.String()
		if strings.EqualFold(strings.TrimSpace(idStr), user) ||
			strings.EqualFold(strings.TrimSpace(members[i].Email), user) {
			return []access.Entitlement{{
				ResourceExternalID: groupID,
				Role:               "member",
				Source:             "direct",
			}}, nil
		}
	}
	return nil, nil
}

func knowbe4OptionalGroupID(raw map[string]interface{}) string {
	if raw == nil {
		return ""
	}
	if v, ok := raw["group_id"].(string); ok {
		return strings.TrimSpace(v)
	}
	if v, ok := raw["group_id"].(float64); ok {
		return fmt.Sprintf("%d", int64(v))
	}
	return ""
}
