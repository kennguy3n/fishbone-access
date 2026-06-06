// Package launchdarkly — GroupSyncer implementation.
//
// LaunchDarkly models a "group" as a Team. Teams live at GET
// /api/v2/teams (limit/offset paginated, same scheme as the
// pre-existing SyncIdentities). Each team's members are returned by
// the dedicated members listing endpoint GET
// /api/v2/teams/{teamKey}/members (also limit/offset). The members
// endpoint returns full member objects whose stable identifier is
// `_id` (consistent with the top-level account-member listing in
// connector.go), NOT the `memberId` field that appears on embedded
// team-detail responses.
package launchdarkly

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type ldTeam struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type ldTeamsListResponse struct {
	TotalCount int      `json:"totalCount"`
	Items      []ldTeam `json:"items"`
}

type ldTeamMember struct {
	MemberID string `json:"_id"`
}

type ldTeamMembersResponse struct {
	TotalCount int            `json:"totalCount"`
	Items      []ldTeamMember `json:"items"`
}

// CountGroups walks SyncGroups and tallies every page.
func (c *LaunchDarklyAccessConnector) CountGroups(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	total := 0
	err := c.SyncGroups(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		total += len(b)
		return nil
	})
	return total, err
}

// SyncGroups paginates /api/v2/teams using the LaunchDarkly
// limit/offset scheme already established by SyncIdentities. Each
// Identity is type IdentityTypeGroup with ExternalID set to the team
// `key` (LaunchDarkly's stable identifier).
func (c *LaunchDarklyAccessConnector) SyncGroups(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	offset := 0
	if checkpoint != "" {
		if v, err := strconv.Atoi(checkpoint); err == nil && v >= 0 {
			offset = v
		}
	}
	base := c.baseURL()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		path := fmt.Sprintf("%s/api/v2/teams?limit=%d&offset=%d", base, pageSize, offset)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp ldTeamsListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("launchdarkly: decode teams: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Items))
		for _, t := range resp.Items {
			display := t.Name
			if display == "" {
				display = t.Key
			}
			identities = append(identities, &access.Identity{
				ExternalID:  t.Key,
				Type:        access.IdentityTypeGroup,
				DisplayName: display,
				Status:      "active",
			})
		}
		next := ""
		// Use the API-reported TotalCount for pagination so we don't
		// (a) make an extra empty request when the team count is an
		// exact multiple of pageSize, or (b) stop early on a
		// well-behaved short page. This matches the pattern used by
		// SyncIdentities in connector.go for the same API.
		if offset+len(resp.Items) < resp.TotalCount && len(resp.Items) > 0 {
			next = strconv.Itoa(offset + len(resp.Items))
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		offset += len(resp.Items)
	}
}

// SyncGroupMembers paginates /api/v2/teams/{teamKey}/members and
// emits the member account IDs assigned to the team. groupExternalID
// must be the team key surfaced by SyncGroups.
func (c *LaunchDarklyAccessConnector) SyncGroupMembers(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	groupExternalID, checkpoint string,
	handler func(memberExternalIDs []string, nextCheckpoint string) error,
) error {
	if groupExternalID == "" {
		return errors.New("launchdarkly: group external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	offset := 0
	if checkpoint != "" {
		if v, err := strconv.Atoi(checkpoint); err == nil && v >= 0 {
			offset = v
		}
	}
	base := c.baseURL()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		path := fmt.Sprintf("%s/api/v2/teams/%s/members?limit=%d&offset=%d",
			base, url.PathEscape(groupExternalID), pageSize, offset)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp ldTeamMembersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("launchdarkly: decode team members: %w", err)
		}
		ids := make([]string, 0, len(resp.Items))
		for _, m := range resp.Items {
			if m.MemberID != "" {
				ids = append(ids, m.MemberID)
			}
		}
		next := ""
		if offset+len(resp.Items) < resp.TotalCount && len(resp.Items) > 0 {
			next = strconv.Itoa(offset + len(resp.Items))
		}
		if err := handler(ids, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		offset += len(resp.Items)
	}
}

var _ access.GroupSyncer = (*LaunchDarklyAccessConnector)(nil)
