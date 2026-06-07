package klaviyo

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

// advanced-capability mapping for klaviyo:
//
//   - ProvisionAccess  -> POST   /api/lists/{list_id}/relationships/profiles
//   - RevokeAccess     -> DELETE /api/lists/{list_id}/relationships/profiles
//   - ListEntitlements -> GET    /api/lists/{list_id}/relationships/profiles
//
// AccessGrant maps:
//   - grant.UserExternalID     -> Klaviyo profile id
//   - grant.ResourceExternalID -> list id
//
// Klaviyo-API-Key header auth reuses the existing connector.newRequest
// helper. Idempotent on (UserExternalID, ResourceExternalID): Klaviyo
// returns 400/409 for duplicate add and 404 for already-removed.

func klaviyoValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("klaviyo: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("klaviyo: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *KlaviyoAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("klaviyo: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *KlaviyoAccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	var rdr io.Reader
	if len(body) > 0 {
		rdr = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.api+json")
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/vnd.api+json")
	}
	req.Header.Set("Authorization", "Klaviyo-API-Key "+strings.TrimSpace(secrets.APIKey))
	req.Header.Set("revision", apiRevision)
	return req, nil
}

func klaviyoMembershipURL(base, listID string) string {
	return base + "/api/lists/" + url.PathEscape(strings.TrimSpace(listID)) + "/relationships/profiles"
}

func klaviyoMembershipPayload(profileID string) []byte {
	payload, _ := json.Marshal(map[string]interface{}{
		"data": []map[string]string{
			{"type": "profile", "id": strings.TrimSpace(profileID)},
		},
	})
	return payload
}

func (c *KlaviyoAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := klaviyoValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	endpoint := klaviyoMembershipURL(c.baseURL(), grant.ResourceExternalID)
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, endpoint, klaviyoMembershipPayload(grant.UserExternalID))
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
		return fmt.Errorf("klaviyo: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("klaviyo: provision status %d: %s", status, string(body))
	}
}

func (c *KlaviyoAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := klaviyoValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	endpoint := klaviyoMembershipURL(c.baseURL(), grant.ResourceExternalID)
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete, endpoint, klaviyoMembershipPayload(grant.UserExternalID))
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
		return fmt.Errorf("klaviyo: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("klaviyo: revoke status %d: %s", status, string(body))
	}
}

func (c *KlaviyoAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	profile := strings.TrimSpace(userExternalID)
	if profile == "" {
		return nil, errors.New("klaviyo: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	// List the profile's list memberships via /api/profiles/{id}/relationships/lists.
	endpoint := c.baseURL() + "/api/profiles/" + url.PathEscape(profile) + "/relationships/lists"
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
		return nil, fmt.Errorf("klaviyo: list entitlements status %d: %s", status, string(body))
	}
	var envelope struct {
		Data []struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("klaviyo: decode entitlements: %w", err)
	}
	out := make([]access.Entitlement, 0, len(envelope.Data))
	for _, d := range envelope.Data {
		out = append(out, access.Entitlement{
			ResourceExternalID: strings.TrimSpace(d.ID),
			Role:               "list-member",
			Source:             "direct",
		})
	}
	return out, nil
}
