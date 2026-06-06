// Package datadog — GroupSyncer implementation.
//
// Datadog models org-level "groups" as Teams under
// /api/v2/teams. Team memberships live at
// /api/v2/teams/{team_id}/memberships. Both endpoints use the same
// JSON:API page[number]/page[size] pagination as /api/v2/users.
package datadog

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type ddTeam struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		Handle      string `json:"handle"`
		Name        string `json:"name"`
		Description string `json:"description"`
	} `json:"attributes"`
}

type ddTeamMembership struct {
	ID            string `json:"id"`
	Type          string `json:"type"`
	Relationships struct {
		User struct {
			Data struct {
				ID   string `json:"id"`
				Type string `json:"type"`
			} `json:"data"`
		} `json:"user"`
	} `json:"relationships"`
}

// CountGroups streams SyncGroups and tallies each batch. Datadog
// exposes a `meta.page.total_count` but it counts users, not teams
// — paging through SyncGroups gives the authoritative number.
func (c *DatadogAccessConnector) CountGroups(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	total := 0
	err := c.SyncGroups(ctx, configRaw, secretsRaw, "", func(batch []*access.Identity, _ string) error {
		total += len(batch)
		return nil
	})
	return total, err
}

// SyncGroups paginates /api/v2/teams with `page[number]/page[size]`.
// Each Team becomes a Group-typed Identity envelope whose ExternalID
// is the team UUID.
func (c *DatadogAccessConnector) SyncGroups(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	page := 0
	if checkpoint != "" {
		_, _ = fmt.Sscanf(checkpoint, "%d", &page)
		if page < 0 {
			page = 0
		}
	}
	base := c.baseURL(cfg)
	for {
		url := fmt.Sprintf("%s/api/v2/teams?page%%5Bnumber%%5D=%d&page%%5Bsize%%5D=%d", base, page, pageSize)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, url)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp struct {
			Data []ddTeam `json:"data"`
			Meta struct {
				Page struct {
					TotalCount int `json:"total_count"`
				} `json:"page"`
			} `json:"meta"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("datadog: decode teams: %w", err)
		}
		groups := make([]*access.Identity, 0, len(resp.Data))
		for _, t := range resp.Data {
			display := strings.TrimSpace(t.Attributes.Name)
			if display == "" {
				display = t.Attributes.Handle
			}
			groups = append(groups, &access.Identity{
				ExternalID:  t.ID,
				Type:        access.IdentityTypeGroup,
				DisplayName: display,
				Status:      "active",
			})
		}
		next := ""
		if (page+1)*pageSize < resp.Meta.Page.TotalCount && len(resp.Data) > 0 {
			next = fmt.Sprintf("%d", page+1)
		}
		if err := handler(groups, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		page++
	}
}

// SyncGroupMembers paginates /api/v2/teams/{team_id}/memberships and
// projects each relationship onto a user external ID.
func (c *DatadogAccessConnector) SyncGroupMembers(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	groupExternalID, checkpoint string,
	handler func(memberExternalIDs []string, nextCheckpoint string) error,
) error {
	if strings.TrimSpace(groupExternalID) == "" {
		return fmt.Errorf("datadog: group external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	page := 0
	if checkpoint != "" {
		_, _ = fmt.Sscanf(checkpoint, "%d", &page)
		if page < 0 {
			page = 0
		}
	}
	base := c.baseURL(cfg)
	for {
		endpoint := fmt.Sprintf("%s/api/v2/teams/%s/memberships?page%%5Bnumber%%5D=%d&page%%5Bsize%%5D=%d",
			base, url.PathEscape(groupExternalID), page, pageSize)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, endpoint)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp struct {
			Data []ddTeamMembership `json:"data"`
			Meta struct {
				Page struct {
					TotalCount int `json:"total_count"`
				} `json:"page"`
			} `json:"meta"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("datadog: decode memberships: %w", err)
		}
		ids := make([]string, 0, len(resp.Data))
		for _, m := range resp.Data {
			if uid := strings.TrimSpace(m.Relationships.User.Data.ID); uid != "" {
				ids = append(ids, uid)
			}
		}
		next := ""
		if (page+1)*pageSize < resp.Meta.Page.TotalCount && len(resp.Data) > 0 {
			next = fmt.Sprintf("%d", page+1)
		}
		if err := handler(ids, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		page++
	}
}

var _ access.GroupSyncer = (*DatadogAccessConnector)(nil)
