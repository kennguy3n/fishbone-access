// Package front — SessionRevoker via PATCH /teammates/{id} with
// is_blocked=true.
//
// Front does not expose a session-only revocation endpoint, but the
// documented `is_blocked` flag on the teammate object is the
// company-wide kill switch: when set, the teammate cannot sign in,
// cannot access conversations, and existing API tokens issued in
// their name stop authenticating. The flag is reversible, so the
// kill is recoverable if HR later restores the leaver.
//
// Endpoint:  PATCH /teammates/{teammate_id}
// Body:      {"is_blocked": true}
// 200/204    -> success
// 404        -> idempotent success (teammate already gone)
package front

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

func (c *FrontAccessConnector) RevokeUserSessions(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) error {
	userExternalID = strings.TrimSpace(userExternalID)
	if userExternalID == "" {
		return errors.New("front: session revoke: userExternalID is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	target := c.baseURL() + "/teammates/" + url.PathEscape(userExternalID)
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPatch, target, []byte(`{"is_blocked":true}`))
	if err != nil {
		return err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusAccepted, http.StatusNotFound:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return fmt.Errorf("front: session revoke status %d: %s", resp.StatusCode, string(body))
}

var _ access.SessionRevoker = (*FrontAccessConnector)(nil)
