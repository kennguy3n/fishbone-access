// Package slack — GroupSyncer implementation.
//
// Slack models "groups" as User Groups (formerly "Slack User Groups";
// aka "@usergroup mentions"). /usergroups.list returns the workspace
// roster, while /usergroups.users.list dumps the members of a single
// group. Both endpoints are cursor-paginated through the same
// response_metadata.next_cursor convention used by users.list.
package slack

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// slackUserGroup is the minimal projection of a usergroup record
// surfaced by /usergroups.list. We keep DateDelete so we can mark
// archived groups as removed at the platform layer.
type slackUserGroup struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Handle      string `json:"handle"`
	Description string `json:"description"`
	DateDelete  int64  `json:"date_delete"`
	IsActive    bool   `json:"-"`
}

type slackUserGroupsResponse struct {
	OK               bool             `json:"ok"`
	Error            string           `json:"error,omitempty"`
	UserGroups       []slackUserGroup `json:"usergroups"`
	ResponseMetadata struct {
		NextCursor string `json:"next_cursor"`
	} `json:"response_metadata"`
}

type slackUserGroupMembersResponse struct {
	OK               bool     `json:"ok"`
	Error            string   `json:"error,omitempty"`
	Users            []string `json:"users"`
	ResponseMetadata struct {
		NextCursor string `json:"next_cursor"`
	} `json:"response_metadata"`
}

// CountGroups returns the count of user groups in the workspace by
// streaming SyncGroups and tallying every batch. Slack does not
// expose a count probe so this is the cheapest portable shape.
func (c *SlackAccessConnector) CountGroups(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	total := 0
	err := c.SyncGroups(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		total += len(b)
		return nil
	})
	return total, err
}

// SyncGroups paginates /usergroups.list. The Slack API takes a
// boolean include_disabled query parameter; we default to false so
// the sync mirrors the active-only view the admin UI surfaces.
func (c *SlackAccessConnector) SyncGroups(
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
	for {
		q := url.Values{}
		q.Set("include_count", "true")
		q.Set("include_disabled", "false")
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		path := "/usergroups.list?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp slackUserGroupsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("slack: decode usergroups.list: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.UserGroups))
		for _, g := range resp.UserGroups {
			status := "active"
			if g.DateDelete != 0 {
				status = "archived"
			}
			identities = append(identities, &access.Identity{
				ExternalID:  g.ID,
				Type:        access.IdentityTypeGroup,
				DisplayName: g.Name,
				Status:      status,
			})
		}
		next := resp.ResponseMetadata.NextCursor
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		cursor = next
	}
}

// SyncGroupMembers paginates /usergroups.users.list for one group.
// Slack returns a flat array of user IDs (no full user envelopes)
// which is exactly the shape the platform-wide handler expects.
func (c *SlackAccessConnector) SyncGroupMembers(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	groupExternalID, checkpoint string,
	handler func(memberExternalIDs []string, nextCheckpoint string) error,
) error {
	if groupExternalID == "" {
		return fmt.Errorf("slack: group external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	cursor := checkpoint
	for {
		q := url.Values{}
		q.Set("usergroup", groupExternalID)
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		path := "/usergroups.users.list?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp slackUserGroupMembersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("slack: decode usergroups.users.list: %w", err)
		}
		next := resp.ResponseMetadata.NextCursor
		if err := handler(resp.Users, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		cursor = next
	}
}
