package datadog

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// RevokeUserSessions implements access.SessionRevoker for Datadog.
//
// Datadog does not expose a dedicated "terminate sessions" endpoint
// — the canonical kill-switch path is PATCH /api/v2/users/{id} with
// `disabled: true`, which immediately revokes the user's API and
// web-app session tokens and forces a fresh login (which the IdP
// will reject once the user is disabled in the upstream directory).
//
// 200 / 204 are success. 404 means the user is already gone and is
// treated as success (idempotent kill switch per the leaver
// contract). Any other status returns a non-nil err so the leaver
// flow logs it but continues to the next kill-switch layer.
func (c *DatadogAccessConnector) RevokeUserSessions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) error {
	if userExternalID == "" {
		return fmt.Errorf("datadog: session revoke: userExternalID is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]interface{}{
		"data": map[string]interface{}{
			"type": "users",
			"id":   userExternalID,
			"attributes": map[string]interface{}{
				"disabled": true,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("datadog: session revoke marshal: %w", err)
	}
	endpoint := c.baseURL(cfg) + "/api/v2/users/" + url.PathEscape(userExternalID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DD-API-KEY", strings.TrimSpace(secrets.APIKey))
	req.Header.Set("DD-APPLICATION-KEY", strings.TrimSpace(secrets.ApplicationKey))
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("datadog: session revoke: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusNotFound:
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("datadog: session revoke status %d: %s", resp.StatusCode, string(body))
}

var _ access.SessionRevoker = (*DatadogAccessConnector)(nil)
