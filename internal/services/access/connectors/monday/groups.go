// Package monday — GroupSyncer implementation.
//
// Monday.com models a "group" as a Team. SyncGroups paginates the
// teams collection and SyncGroupMembers refetches per-team
// memberships on demand:
//
//	SyncGroups        — query { teams(limit: N, page: P) { id name } }
//	                    (only id+name are needed downstream;
//	                    users{id} is intentionally NOT requested
//	                    here to keep the per-page complexity
//	                    well under Monday's budget)
//	SyncGroupMembers  — query { teams(ids: [T]) { id users { id } } }
//
// We use limit/page pagination on the outer teams collection.
// Monday does not expose a paginated per-team-members endpoint, so
// SyncGroupMembers fetches the full user list inline and emits it
// in a single handler invocation. Realistic team sizes (typically
// < 200 users) make this safe; if a tenant exceeds the inline-cap
// we surface the partial set and let the caller refresh on next
// sync.
package monday

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const teamsPageSize = 50

type mondayTeam struct {
	ID    json.Number `json:"id"`
	Name  string      `json:"name"`
	Users []struct {
		ID json.Number `json:"id"`
	} `json:"users"`
}

type graphQLTeamsResponse struct {
	Data struct {
		Teams []mondayTeam `json:"teams"`
	} `json:"data"`
	Errors []graphQLError `json:"errors,omitempty"`
}

// CountGroups walks SyncGroups and tallies every page.
func (c *MondayAccessConnector) CountGroups(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	total := 0
	err := c.SyncGroups(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		total += len(b)
		return nil
	})
	return total, err
}

// SyncGroups paginates the GraphQL `teams` collection. Each Identity
// emits the team's numeric id as ExternalID and is typed as
// IdentityTypeGroup.
func (c *MondayAccessConnector) SyncGroups(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	page := 1
	if checkpoint != "" {
		if p, err := strconv.Atoi(checkpoint); err == nil && p > 0 {
			page = p
		}
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		query := fmt.Sprintf(
			"query { teams(limit: %d, page: %d) { id name } }",
			teamsPageSize, page,
		)
		body, err := c.postRaw(ctx, secrets, query)
		if err != nil {
			return err
		}
		var resp graphQLTeamsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("monday: decode teams: %w", err)
		}
		if len(resp.Errors) > 0 {
			return fmt.Errorf("monday: teams graphql error: %s", resp.Errors[0].Message)
		}
		identities := make([]*access.Identity, 0, len(resp.Data.Teams))
		for _, t := range resp.Data.Teams {
			display := t.Name
			if display == "" {
				display = t.ID.String()
			}
			identities = append(identities, &access.Identity{
				ExternalID:  t.ID.String(),
				Type:        access.IdentityTypeGroup,
				DisplayName: display,
				Status:      "active",
			})
		}
		next := ""
		if len(resp.Data.Teams) >= teamsPageSize {
			next = strconv.Itoa(page + 1)
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		page++
	}
}

// SyncGroupMembers re-queries the team detail (Monday's GraphQL has
// no per-team-members paginated endpoint, so we fetch the team's
// inline `users { id }` and emit them in a single handler invocation).
// groupExternalID must be the numeric team id surfaced by SyncGroups.
func (c *MondayAccessConnector) SyncGroupMembers(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	groupExternalID, _ string,
	handler func(memberExternalIDs []string, nextCheckpoint string) error,
) error {
	teamID, err := parseMondayID("group_external_id", groupExternalID)
	if err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	query := fmt.Sprintf("query { teams(ids: [%s]) { id users { id } } }", teamID)
	body, err := c.postRaw(ctx, secrets, query)
	if err != nil {
		return err
	}
	var resp graphQLTeamsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("monday: decode team members: %w", err)
	}
	if len(resp.Errors) > 0 {
		return fmt.Errorf("monday: team members graphql error: %s", resp.Errors[0].Message)
	}
	if len(resp.Data.Teams) == 0 {
		// Non-nil empty slice per GroupSyncer empty-batch contract —
		// see optional_interfaces.go.
		return handler([]string{}, "")
	}
	ids := make([]string, 0, len(resp.Data.Teams[0].Users))
	for _, u := range resp.Data.Teams[0].Users {
		if s := u.ID.String(); s != "" {
			ids = append(ids, s)
		}
	}
	return handler(ids, "")
}

var _ access.GroupSyncer = (*MondayAccessConnector)(nil)
