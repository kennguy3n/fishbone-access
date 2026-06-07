package bamboohr

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// Compile-time assertion that the connector satisfies the optional
// SessionRevoker capability, mirroring the azure connector. If the
// interface changes this fails to build rather than silently
// dropping the capability at registration time.
var _ access.SessionRevoker = (*BambooHRAccessConnector)(nil)

// RevokeUserSessions implements access.SessionRevoker for
// BambooHR. The employee-termination endpoint
// PUT /v1/employees/{id}/terminateEmployee marks the employee as
// terminated which deactivates their HR account; BambooHR
// invalidates every active web session and refresh token for the
// supplied employee as a side-effect of the termination, forcing
// the next sign-in to round-trip the federated IdP.
//
// userExternalID is the BambooHR employee identifier (the same
// value SyncIdentities emits as Identity.ExternalID). 200 / 204
// means propagated; 404 means the employee is already gone and is
// treated as success (idempotent kill switch per the leaver contract). Any
// other status returns a non-nil err so the leaver flow logs it
// but continues to the next kill-switch layer.
func (c *BambooHRAccessConnector) RevokeUserSessions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) error {
	if userExternalID == "" {
		return fmt.Errorf("bamboohr: session revoke: userExternalID is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]interface{}{
		"terminationReasonId": 0,
	})
	if err != nil {
		return fmt.Errorf("bamboohr: session revoke: marshal payload: %w", err)
	}
	fullURL := c.baseURL(cfg) + "/v1/employees/" + url.PathEscape(userExternalID) + "/terminateEmployee"
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, fullURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	creds := strings.TrimSpace(secrets.APIKey) + ":x"
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("bamboohr: session revoke: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusNotFound:
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("bamboohr: session revoke status %d: %s", resp.StatusCode, string(body))
}
