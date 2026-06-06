// Package intercom — GroupSyncer over the Intercom Teams API.
//
// Intercom models conversation-assignment groups as "Teams". The
// public REST API exposes:
//
//	GET /teams              -> { "teams": [ {id,name,admin_ids:[...]} ] }
//	GET /teams/{id}         -> { id, name, admin_ids: [...] }
//
// Intercom returns every team in a single response; there is no
// documented pagination on `/teams` (the response is bounded by the
// workspace's team count, which is small in practice). GroupSyncer
// implementations are nevertheless required to honour the
// (checkpoint, handler) contract from access.optional_interfaces.go,
// so SyncGroups / SyncGroupMembers still call the handler once with
// an empty next-checkpoint.
//
// ExternalID is the Intercom team id (a stable numeric string).
// Membership is sourced from each team's `admin_ids` array, which
// already lists every admin (no per-team paginated endpoint).
package intercom

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// CountGroups returns the total number of Intercom teams.
func (c *IntercomAccessConnector) CountGroups(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, c.baseURL()+"/teams")
	if err != nil {
		return 0, err
	}
	body, err := c.do(req)
	if err != nil {
		return 0, err
	}
	var resp intercomTeamsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return 0, err
	}
	return len(resp.Teams), nil
}

// SyncGroups walks /teams and emits one Identity per team. The
// handler is invoked exactly once with an empty next-checkpoint —
// Intercom returns every team in a single response.
func (c *IntercomAccessConnector) SyncGroups(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	_ string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, c.baseURL()+"/teams")
	if err != nil {
		return err
	}
	body, err := c.do(req)
	if err != nil {
		return err
	}
	var resp intercomTeamsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return err
	}
	identities := make([]*access.Identity, 0, len(resp.Teams))
	for _, tm := range resp.Teams {
		identities = append(identities, &access.Identity{
			ExternalID:  tm.ID,
			Type:        access.IdentityTypeGroup,
			DisplayName: tm.Name,
			Status:      "active",
			RawData:     map[string]interface{}{"admin_count": len(tm.AdminIDs)},
		})
	}
	return handler(identities, "")
}

// SyncGroupMembers fetches /teams/{id} and emits every admin id in
// the team's `admin_ids` array as a member external id. The handler
// is invoked exactly once with an empty next-checkpoint — Intercom
// returns the full membership in a single GET. 404 on the team
// returns an empty membership (the team is already gone).
func (c *IntercomAccessConnector) SyncGroupMembers(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	groupExternalID, _ string,
	handler func(memberExternalIDs []string, nextCheckpoint string) error,
) error {
	groupExternalID = strings.TrimSpace(groupExternalID)
	if groupExternalID == "" {
		return errors.New("intercom: sync group members: groupExternalID is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	team, err := c.getTeam(ctx, secrets, groupExternalID)
	if err != nil {
		return err
	}
	if team == nil {
		// Always pass a non-nil empty slice so downstream callers
		// that JSON-serialise the membership see `[]` rather than
		// `null` and so range / len semantics are identical to the
		// non-404 path. This matches docker_hub and pagerduty.
		return handler([]string{}, "")
	}
	ids := make([]string, 0, len(team.AdminIDs))
	for _, a := range team.AdminIDs {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		ids = append(ids, a)
	}
	return handler(ids, "")
}

var _ access.GroupSyncer = (*IntercomAccessConnector)(nil)
