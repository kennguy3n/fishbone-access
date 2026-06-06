// Package docker_hub — GroupSyncer over the Docker Hub orgs API.
//
// Docker Hub Business/Team organisations expose first-class "groups"
// (formerly "teams") at:
//
//	GET /v2/orgs/{name}/groups?page=...&page_size=...
//	GET /v2/orgs/{name}/groups/{group_name}/members?page=...&page_size=...
//
// Both endpoints share the same paginated envelope as
// `/v2/orgs/{name}/members` — a `count/next/previous/results` shape
// where `next` is an absolute URL the client follows verbatim.
// GroupExternalID is the group `name` (Docker Hub's stable
// identifier — there is no numeric id surfaced via the public API).
package docker_hub

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

type dockerHubGroup struct {
	ID          int    `json:"id"`
	UUID        string `json:"uuid"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type dockerHubGroupsResponse struct {
	Count    int              `json:"count"`
	Next     string           `json:"next"`
	Previous string           `json:"previous"`
	Results  []dockerHubGroup `json:"results"`
}

// CountGroups walks every page of /v2/orgs/{name}/groups and returns
// the cumulative count. The first page's `count` field is the
// authoritative total; we still pull a single page so the network
// call exercises the same auth + pagination plumbing as SyncGroups
// (no silent reliance on a metadata-only call that may go stale).
func (c *DockerHubAccessConnector) CountGroups(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	token, err := c.login(ctx, secrets)
	if err != nil {
		return 0, err
	}
	org := strings.TrimSpace(cfg.Organization)
	if org == "" {
		return 0, errors.New("docker_hub: count groups: organization is required")
	}
	listURL := fmt.Sprintf("%s/v2/orgs/%s/groups?page=1&page_size=%d", c.baseURL(), url.PathEscape(org), pageSize)
	req, err := c.newRequest(ctx, token, http.MethodGet, listURL)
	if err != nil {
		return 0, err
	}
	body, err := c.do(req)
	if err != nil {
		return 0, err
	}
	var resp dockerHubGroupsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return 0, fmt.Errorf("docker_hub: decode groups count: %w", err)
	}
	if resp.Count > 0 {
		return resp.Count, nil
	}
	// Some org tiers return count=0 even when results are present;
	// fall back to walking the rest of the pages to get a real total.
	total := len(resp.Results)
	next := strings.TrimSpace(resp.Next)
	for next != "" {
		req, err := c.newRequest(ctx, token, http.MethodGet, next)
		if err != nil {
			return 0, err
		}
		body, err := c.do(req)
		if err != nil {
			return 0, err
		}
		var page dockerHubGroupsResponse
		if err := json.Unmarshal(body, &page); err != nil {
			return 0, fmt.Errorf("docker_hub: decode groups count: %w", err)
		}
		total += len(page.Results)
		next = strings.TrimSpace(page.Next)
	}
	return total, nil
}

// SyncGroups paginates /v2/orgs/{name}/groups via the absolute `next`
// URL returned by the upstream. ExternalID is the group name (the
// stable identifier; uuid + numeric id are also surfaced via
// RawData for downstream cross-referencing).
func (c *DockerHubAccessConnector) SyncGroups(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	org := strings.TrimSpace(cfg.Organization)
	if org == "" {
		return errors.New("docker_hub: sync groups: organization is required")
	}
	token, err := c.login(ctx, secrets)
	if err != nil {
		return err
	}
	nextURL := checkpoint
	if nextURL == "" {
		nextURL = fmt.Sprintf("%s/v2/orgs/%s/groups?page=1&page_size=%d", c.baseURL(), url.PathEscape(org), pageSize)
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		req, err := c.newRequest(ctx, token, http.MethodGet, nextURL)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var page dockerHubGroupsResponse
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("docker_hub: decode groups: %w", err)
		}
		identities := make([]*access.Identity, 0, len(page.Results))
		for _, g := range page.Results {
			identities = append(identities, &access.Identity{
				ExternalID:  g.Name,
				Type:        access.IdentityTypeGroup,
				DisplayName: g.Name,
				Status:      "active",
				RawData: map[string]interface{}{
					"id":          g.ID,
					"uuid":        g.UUID,
					"description": g.Description,
				},
			})
		}
		next := strings.TrimSpace(page.Next)
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		nextURL = next
	}
}

// SyncGroupMembers paginates /v2/orgs/{name}/groups/{group}/members
// and emits the upstream `username` for every member (Docker Hub's
// stable identifier — uuid/id may be empty on some org tiers).
func (c *DockerHubAccessConnector) SyncGroupMembers(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	groupExternalID, checkpoint string,
	handler func(memberExternalIDs []string, nextCheckpoint string) error,
) error {
	groupExternalID = strings.TrimSpace(groupExternalID)
	if groupExternalID == "" {
		return errors.New("docker_hub: sync group members: groupExternalID is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	org := strings.TrimSpace(cfg.Organization)
	if org == "" {
		return errors.New("docker_hub: sync group members: organization is required")
	}
	token, err := c.login(ctx, secrets)
	if err != nil {
		return err
	}
	nextURL := checkpoint
	if nextURL == "" {
		nextURL = fmt.Sprintf("%s/v2/orgs/%s/groups/%s/members?page=1&page_size=%d",
			c.baseURL(), url.PathEscape(org), url.PathEscape(groupExternalID), pageSize)
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		req, err := c.newRequest(ctx, token, http.MethodGet, nextURL)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var page dockerHubListResponse
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("docker_hub: decode group members: %w", err)
		}
		ids := make([]string, 0, len(page.Results))
		for _, m := range page.Results {
			if m.Username != "" {
				ids = append(ids, m.Username)
			} else if m.ID != "" {
				ids = append(ids, m.ID)
			}
		}
		next := strings.TrimSpace(page.Next)
		if err := handler(ids, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		nextURL = next
	}
}

var _ access.GroupSyncer = (*DockerHubAccessConnector)(nil)
