// Package figma — SessionRevoker via SCIM DELETE /Users/{id}.
//
// Figma Enterprise's SCIM 2.0 endpoint defines DELETE on /Users/{id}
// as "deactivate this user". The user remains in the Figma audit
// trail but loses access to every team and project, every existing
// access token is invalidated, and the next sign-in attempt is
// blocked at the IdP-federated login step. This matches the leaver-
// flow contract exactly: a one-call kill switch that is idempotent
// (404 = already gone).
//
// Figma's REST API does not expose a separate session-only
// revocation endpoint; SCIM DELETE is the documented kill switch
// for org-wide access. The implementation composes the shared
// access.SCIMClient via scimConfig() / scim() so the auth header,
// base URL normalisation, and 404-as-success handling are all
// inherited from the SCIM provisioner.
package figma

import (
	"context"
	"fmt"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// RevokeUserSessions deactivates the supplied Figma user by issuing
// DELETE {scim_base_url}/Users/{id}. userExternalID is the SCIM
// resource id (Figma's stable internal id, NOT the email). 404 is
// treated as idempotent success.
func (c *FigmaAccessConnector) RevokeUserSessions(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) error {
	userExternalID = strings.TrimSpace(userExternalID)
	if userExternalID == "" {
		return fmt.Errorf("figma: session revoke: userExternalID is required")
	}
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().DeleteSCIMResource(ctx, scimCfg, scimSecrets, "Users", userExternalID)
}

var _ access.SessionRevoker = (*FigmaAccessConnector)(nil)
