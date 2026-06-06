// Package asana — GroupSyncer implementation.
//
// Asana models access groups as Teams scoped to a workspace under
// /organizations/{workspace_gid}/teams. Team rosters live at
// /teams/{team_gid}/users. Both endpoints use the standard
// offset-based pagination via the `next_page` envelope.
package asana

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type asanaTeam struct {
	GID         string `json:"gid"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type asanaTeamsResponse struct {
	Data     []asanaTeam `json:"data"`
	NextPage struct {
		Offset string `json:"offset,omitempty"`
	} `json:"next_page"`
}

type asanaTeamUser struct {
	GID  string `json:"gid"`
	Name string `json:"name,omitempty"`
}

type asanaTeamUsersResponse struct {
	Data     []asanaTeamUser `json:"data"`
	NextPage struct {
		Offset string `json:"offset,omitempty"`
	} `json:"next_page"`
}

// CountGroups streams SyncGroups and tallies each batch.
func (c *AsanaAccessConnector) CountGroups(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	total := 0
	err := c.SyncGroups(ctx, configRaw, secretsRaw, "", func(batch []*access.Identity, _ string) error {
		total += len(batch)
		return nil
	})
	return total, err
}

// SyncGroups paginates /organizations/{workspace_gid}/teams. The
// `organizations` segment is required when scoping by workspace — the
// older /teams/{team_gid} route only works for personal teams and is
// not what we want here.
func (c *AsanaAccessConnector) SyncGroups(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	offset := checkpoint
	for {
		path := "/organizations/" + url.PathEscape(cfg.WorkspaceGID) + "/teams?limit=100&opt_fields=name,description"
		if offset != "" {
			path += "&offset=" + url.QueryEscape(offset)
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp asanaTeamsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("asana: decode teams: %w", err)
		}
		groups := make([]*access.Identity, 0, len(resp.Data))
		for _, t := range resp.Data {
			display := strings.TrimSpace(t.Name)
			if display == "" {
				display = t.GID
			}
			groups = append(groups, &access.Identity{
				ExternalID:  t.GID,
				Type:        access.IdentityTypeGroup,
				DisplayName: display,
				Status:      "active",
			})
		}
		next := resp.NextPage.Offset
		if err := handler(groups, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		offset = next
	}
}

// SyncGroupMembers paginates /teams/{team_gid}/users.
func (c *AsanaAccessConnector) SyncGroupMembers(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	groupExternalID, checkpoint string,
	handler func(memberExternalIDs []string, nextCheckpoint string) error,
) error {
	if strings.TrimSpace(groupExternalID) == "" {
		return fmt.Errorf("asana: group external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	offset := checkpoint
	for {
		path := "/teams/" + url.PathEscape(groupExternalID) + "/users?limit=100&opt_fields=name"
		if offset != "" {
			path += "&offset=" + url.QueryEscape(offset)
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp asanaTeamUsersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("asana: decode team users: %w", err)
		}
		ids := make([]string, 0, len(resp.Data))
		for _, u := range resp.Data {
			if s := strings.TrimSpace(u.GID); s != "" {
				ids = append(ids, s)
			}
		}
		next := resp.NextPage.Offset
		if err := handler(ids, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		offset = next
	}
}

var _ access.GroupSyncer = (*AsanaAccessConnector)(nil)
