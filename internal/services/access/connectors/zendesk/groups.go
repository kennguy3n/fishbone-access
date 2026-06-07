// Package zendesk — GroupSyncer implementation.
//
// Zendesk exposes /api/v2/groups for the group roster and
// /api/v2/group_memberships?group_id={id} for the per-group
// membership. Both endpoints follow Zendesk's cursor pagination
// scheme: each response carries a `next_page` URL until the final
// page returns an empty string.
package zendesk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type zendeskGroup struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type zendeskGroupsResponse struct {
	Groups   []zendeskGroup `json:"groups"`
	NextPage string         `json:"next_page,omitempty"`
}

type zendeskGroupMembership struct {
	UserID  int64 `json:"user_id"`
	GroupID int64 `json:"group_id"`
}

type zendeskGroupMembershipsResponse struct {
	GroupMemberships []zendeskGroupMembership `json:"group_memberships"`
	NextPage         string                   `json:"next_page,omitempty"`
}

// CountGroups streams SyncGroups and tallies every batch. Zendesk
// has a /count endpoint on groups but the streaming shape stays
// uniform with the other GroupSyncer connectors and avoids an
// extra round-trip.
func (c *ZendeskAccessConnector) CountGroups(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	total := 0
	err := c.SyncGroups(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		total += len(b)
		return nil
	})
	return total, err
}

// SyncGroups paginates /api/v2/groups.json using Zendesk's
// next_page cursor. Each group becomes an Identity envelope with
// ExternalID = numeric group ID.
func (c *ZendeskAccessConnector) SyncGroups(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	nextURL := checkpoint
	if nextURL == "" {
		nextURL = c.baseURL(cfg) + "/api/v2/groups.json?per_page=100"
	}
	for {
		req, err := c.newRequest(ctx, secrets, http.MethodGet, nextURL)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp zendeskGroupsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("zendesk: decode groups: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Groups))
		for _, g := range resp.Groups {
			identities = append(identities, &access.Identity{
				ExternalID:  fmt.Sprintf("%d", g.ID),
				Type:        access.IdentityTypeGroup,
				DisplayName: g.Name,
				Status:      "active",
			})
		}
		next := resp.NextPage
		if next != "" && c.urlOverride != "" {
			next = strings.Replace(next, "https://"+cfg.Subdomain+".zendesk.com", strings.TrimRight(c.urlOverride, "/"), 1)
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		nextURL = next
	}
}

// SyncGroupMembers paginates /api/v2/group_memberships.json
// filtered by group_id. Same cursor pagination as SyncGroups.
func (c *ZendeskAccessConnector) SyncGroupMembers(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	groupExternalID, checkpoint string,
	handler func(memberExternalIDs []string, nextCheckpoint string) error,
) error {
	if strings.TrimSpace(groupExternalID) == "" {
		return errors.New("zendesk: group external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	nextURL := checkpoint
	if nextURL == "" {
		nextURL = fmt.Sprintf("%s/api/v2/group_memberships.json?group_id=%s&per_page=100",
			c.baseURL(cfg), url.QueryEscape(groupExternalID))
	}
	for {
		req, err := c.newRequest(ctx, secrets, http.MethodGet, nextURL)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp zendeskGroupMembershipsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("zendesk: decode group memberships: %w", err)
		}
		ids := make([]string, 0, len(resp.GroupMemberships))
		for _, gm := range resp.GroupMemberships {
			ids = append(ids, fmt.Sprintf("%d", gm.UserID))
		}
		next := resp.NextPage
		if next != "" && c.urlOverride != "" {
			next = strings.Replace(next, "https://"+cfg.Subdomain+".zendesk.com", strings.TrimRight(c.urlOverride, "/"), 1)
		}
		if err := handler(ids, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		nextURL = next
	}
}

var _ access.GroupSyncer = (*ZendeskAccessConnector)(nil)
