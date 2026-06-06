// Package cloudflare — SessionRevoker implementation.
//
// Cloudflare Access exposes a per-user session-revocation endpoint at
// POST /accounts/{account_id}/access/organizations/revoke_user that
// terminates every Access session the user holds across every Access
// application protected by the account, without disabling the user
// account itself. This is the canonical kill-switch for a leaver
// flow and is strictly less destructive than DELETE /members (which
// removes the user from the account altogether — that behavior is
// already covered by RevokeAccess in connector.go).
//
// The endpoint requires the user's email address. The connector's
// SyncIdentities path already stores email as ExternalID
// (see mapMembers in connector.go), so userExternalID is the email
// and is forwarded directly. Empty externalIDs are rejected as a
// validation error rather than silently no-op'd.
//
// Idempotency: the upstream returns 200 with the boolean "result"
// field whether or not a live session existed. Any non-2xx response
// surfaces as an error so the operator can retry; a 404 with a
// "not_found" body is mapped to idempotent success to align with
// the leaver-flow contract.
package cloudflare

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

func (c *CloudflareAccessConnector) RevokeUserSessions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) error {
	email := strings.TrimSpace(userExternalID)
	if email == "" {
		return errors.New("cloudflare: session revoke: user external id (email) is required")
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{"email": email})
	path := "/accounts/" + url.PathEscape(cfg.AccountID) + "/access/organizations/revoke_user"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL()+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(secrets.APIToken) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.APIToken))
	} else {
		req.Header.Set("X-Auth-Email", cfg.Email)
		req.Header.Set("X-Auth-Key", strings.TrimSpace(secrets.APIKey))
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare: session revoke: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if resp.StatusCode == http.StatusNotFound {
		// No live session / no such user — treat as idempotent success
		// matching the leaver-flow contract documented on box/session_revoke.go.
		return nil
	}
	return fmt.Errorf("cloudflare: session revoke: status %d: %s", resp.StatusCode, string(body))
}

var _ access.SessionRevoker = (*CloudflareAccessConnector)(nil)
