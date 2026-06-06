// Package monday — SessionRevoker implementation.
//
// Monday.com does not expose a session-only revocation endpoint;
// the canonical kill switch for an account user is the GraphQL
// `deactivate_users` mutation, which both terminates active web /
// mobile / API sessions for the user AND prevents them from
// signing in again until reactivated. This is the same primitive
// used by the leaver-flow in other GraphQL-only providers in this
// codebase (e.g., HubSpot's PATCH-disabled, New Relic's
// userManagementDeleteUser). The destructive semantics are
// documented inline so the leaver flow can surface them.
//
// 200 + a non-empty `data.deactivate_users` array is success; 200
// with a GraphQL error envelope containing "user not found" or
// "already deactivated" is idempotent success; anything else surfaces
// as a non-nil err so the leaver flow can log it and fall through to
// the next kill-switch layer.
package monday

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type deactivateUsersResponse struct {
	Data struct {
		DeactivateUsers []struct {
			ID json.Number `json:"id"`
		} `json:"deactivate_users"`
	} `json:"data"`
	Errors []graphQLError `json:"errors,omitempty"`
}

func (c *MondayAccessConnector) RevokeUserSessions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) error {
	userID, err := parseMondayID("user_external_id", userExternalID)
	if err != nil {
		return fmt.Errorf("monday: session revoke: %w", err)
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	query := fmt.Sprintf("mutation { deactivate_users(user_ids: [%s]) { id } }", userID)
	body, err := c.postRaw(ctx, secrets, query)
	if err != nil {
		return fmt.Errorf("monday: session revoke: %w", err)
	}
	var resp deactivateUsersResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("monday: decode deactivate_users: %w", err)
	}
	if len(resp.Errors) > 0 {
		if graphQLErrorIsIdempotent(resp.Errors, []string{"not found", "already deactivated", "already disabled"}) {
			return nil
		}
		return fmt.Errorf("monday: session revoke graphql error: %s", strings.TrimSpace(resp.Errors[0].Message))
	}
	return nil
}

var _ access.SessionRevoker = (*MondayAccessConnector)(nil)
