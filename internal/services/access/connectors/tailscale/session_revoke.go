// Package tailscale — SessionRevoker implementation.
//
// Tailscale exposes a per-user suspension endpoint at
//
//   POST /api/v2/user/{userId}/suspend
//
// which logs the user out of every device in the tailnet and prevents
// reauthentication until an administrator explicitly restores them.
// Because Tailscale's session model is per-device-keypair (each node
// holds a long-lived auth key), there is no transient "session
// token" to invalidate; suspending the user is the canonical
// kill-switch for the leaver flow. The user account itself is NOT
// deleted — it stays in the directory in a suspended state so the
// audit log retains attribution.
//
// userExternalID is the Tailscale user.id captured by SyncIdentities
// (see connector.go::SyncIdentities → ExternalID: u.ID). Empty
// external IDs are rejected as a validation error rather than
// silently no-op'd.
//
// Idempotency: 200/204 → success; 404 → idempotent success per the
// leaver-flow contract (user already removed); 4xx-with-already-
// suspended response body also folds to success because the user
// is in the desired post-revoke state.
package tailscale

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func (c *TailscaleAccessConnector) RevokeUserSessions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) error {
	userID := strings.TrimSpace(userExternalID)
	if userID == "" {
		return errors.New("tailscale: session revoke: user external id is required")
	}
	_, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	path := "/api/v2/user/" + url.PathEscape(userID) + "/suspend"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL()+path, bytes.NewReader(nil))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(strings.TrimSpace(secrets.APIKey), "")
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("tailscale: session revoke: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if resp.StatusCode == http.StatusNotFound {
		// User already removed from tailnet — idempotent success.
		return nil
	}
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		// Tailscale returns 4xx with a body like {"message":"user is already suspended"}
		// for the second-suspension case. The user is in the desired
		// post-revoke state so fold this to success.
		lower := strings.ToLower(string(body))
		if strings.Contains(lower, "already suspended") || strings.Contains(lower, "already disabled") {
			return nil
		}
	}
	return fmt.Errorf("tailscale: session revoke: status %d: %s", resp.StatusCode, string(body))
}

var _ access.SessionRevoker = (*TailscaleAccessConnector)(nil)
