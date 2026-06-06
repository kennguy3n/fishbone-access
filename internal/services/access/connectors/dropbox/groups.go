// Package dropbox — GroupSyncer implementation.
//
// Dropbox Business groups are enumerated by POST /2/team/groups/list
// and continued via /2/team/groups/list/continue. Group membership
// uses POST /2/team/groups/members/list and continues via
// /2/team/groups/members/list/continue. Both APIs follow the
// canonical cursor + has_more pattern shared with the team members
// list endpoints.
package dropbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type dropboxGroupSummary struct {
	GroupID         string `json:"group_id"`
	GroupName       string `json:"group_name"`
	GroupExternalID string `json:"group_external_id,omitempty"`
	MemberCount     int    `json:"member_count,omitempty"`
}

type dropboxGroupsListResponse struct {
	Groups  []dropboxGroupSummary `json:"groups"`
	Cursor  string                `json:"cursor"`
	HasMore bool                  `json:"has_more"`
}

type dropboxGroupMember struct {
	Profile dropboxProfile `json:"profile"`
}

type dropboxGroupMembersResponse struct {
	Members []dropboxGroupMember `json:"members"`
	Cursor  string               `json:"cursor"`
	HasMore bool                 `json:"has_more"`
}

// CountGroups walks SyncGroups and tallies every page.
func (c *DropboxAccessConnector) CountGroups(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	total := 0
	err := c.SyncGroups(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		total += len(b)
		return nil
	})
	return total, err
}

// SyncGroups paginates /2/team/groups/list using cursor + has_more.
// The checkpoint is the opaque cursor returned by the previous page.
func (c *DropboxAccessConnector) SyncGroups(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	cursor := checkpoint
	base := c.baseURL()
	for {
		var url string
		var payload interface{}
		if cursor == "" {
			url = base + "/2/team/groups/list"
			payload = map[string]interface{}{"limit": pageSize}
		} else {
			url = base + "/2/team/groups/list/continue"
			payload = map[string]interface{}{"cursor": cursor}
		}
		body, err := c.postJSON(ctx, secrets, url, payload)
		if err != nil {
			return err
		}
		var resp dropboxGroupsListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("dropbox: decode groups: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Groups))
		for _, g := range resp.Groups {
			identities = append(identities, &access.Identity{
				ExternalID:  g.GroupID,
				Type:        access.IdentityTypeGroup,
				DisplayName: g.GroupName,
				Status:      "active",
			})
		}
		next := ""
		if resp.HasMore {
			next = resp.Cursor
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		cursor = next
	}
}

// SyncGroupMembers paginates /2/team/groups/members/list using
// cursor + has_more.
func (c *DropboxAccessConnector) SyncGroupMembers(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	groupExternalID, checkpoint string,
	handler func(memberExternalIDs []string, nextCheckpoint string) error,
) error {
	if strings.TrimSpace(groupExternalID) == "" {
		return errors.New("dropbox: group external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	cursor := checkpoint
	base := c.baseURL()
	for {
		var url string
		var payload interface{}
		if cursor == "" {
			url = base + "/2/team/groups/members/list"
			payload = map[string]interface{}{
				"group": map[string]interface{}{
					".tag":     "group_id",
					"group_id": groupExternalID,
				},
				"limit": pageSize,
			}
		} else {
			url = base + "/2/team/groups/members/list/continue"
			payload = map[string]interface{}{"cursor": cursor}
		}
		body, err := c.postJSON(ctx, secrets, url, payload)
		if err != nil {
			return err
		}
		var resp dropboxGroupMembersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("dropbox: decode group members: %w", err)
		}
		ids := make([]string, 0, len(resp.Members))
		for _, m := range resp.Members {
			id := strings.TrimSpace(m.Profile.TeamMemberID)
			if id == "" {
				continue
			}
			ids = append(ids, id)
		}
		next := ""
		if resp.HasMore {
			next = resp.Cursor
		}
		if err := handler(ids, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		cursor = next
	}
}

var _ access.GroupSyncer = (*DropboxAccessConnector)(nil)
