// Package asana — SessionRevoker via SCIM /Users deactivation.
//
// Asana Enterprise's SCIM 2.0 endpoint defines DELETE on /Users/{id}
// as "deactivate this user across every SCIM-managed workspace". The
// account loses access to every team, project, and task; every
// existing access token is invalidated; and the next sign-in attempt
// is blocked at the IdP-federated login. This matches the leaver-
// flow contract exactly: a one-call kill switch that is idempotent
// (404 = already gone).
//
// Asana's REST API exposes a per-workspace removal endpoint
// (POST /workspaces/{gid}/removeUser) but that only detaches the
// user from a single workspace — for a leaver, the SCIM deactivation
// covers every workspace at once and is the right semantic.
package asana

import (
	"context"
	"fmt"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// RevokeUserSessions deactivates the supplied Asana user by issuing
// DELETE {scim_base_url}/Users/{id}. userExternalID is the SCIM
// resource id (Asana's stable internal user gid). 404 is treated as
// idempotent success.
func (c *AsanaAccessConnector) RevokeUserSessions(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) error {
	userExternalID = strings.TrimSpace(userExternalID)
	if userExternalID == "" {
		return fmt.Errorf("asana: session revoke: userExternalID is required")
	}
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().DeleteSCIMResource(ctx, scimCfg, scimSecrets, "Users", userExternalID)
}

var _ access.SessionRevoker = (*AsanaAccessConnector)(nil)
