// Package zoom — GroupSyncer implementation.
//
// Zoom Server-to-Server OAuth groups live under /v2/groups. The list
// endpoint uses page-number pagination (page_number + page_count) and
// the per-group membership endpoint at /v2/groups/{groupId}/members
// follows the same scheme.
package zoom

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type zoomGroup struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	TotalMembers int    `json:"total_members,omitempty"`
}

type zoomGroupsResponse struct {
	PageCount    int         `json:"page_count"`
	PageNumber   int         `json:"page_number"`
	PageSize     int         `json:"page_size"`
	TotalRecords int         `json:"total_records"`
	Groups       []zoomGroup `json:"groups"`
}

type zoomGroupMember struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

type zoomGroupMembersResponse struct {
	PageCount    int               `json:"page_count"`
	PageNumber   int               `json:"page_number"`
	PageSize     int               `json:"page_size"`
	TotalRecords int               `json:"total_records"`
	Members      []zoomGroupMember `json:"members"`
}

// CountGroups walks SyncGroups and tallies every page.
func (c *ZoomAccessConnector) CountGroups(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	total := 0
	err := c.SyncGroups(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		total += len(b)
		return nil
	})
	return total, err
}

// SyncGroups paginates /v2/groups via page_number. The checkpoint is
// the decimal-encoded next page number when more pages remain.
func (c *ZoomAccessConnector) SyncGroups(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	tok, err := c.accessToken(ctx, cfg, secrets)
	if err != nil {
		return err
	}
	page := 1
	if checkpoint != "" {
		if n, err := strconv.Atoi(checkpoint); err == nil && n > 0 {
			page = n
		}
	}
	for {
		path := fmt.Sprintf("/groups?page_size=300&page_number=%d", page)
		req, err := c.newRequest(ctx, tok, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp zoomGroupsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("zoom: decode groups: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Groups))
		for _, g := range resp.Groups {
			identities = append(identities, &access.Identity{
				ExternalID:  g.ID,
				Type:        access.IdentityTypeGroup,
				DisplayName: g.Name,
				Status:      "active",
			})
		}
		next := ""
		if resp.PageCount > page {
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

// SyncGroupMembers paginates /v2/groups/{groupId}/members via
// page_number.
func (c *ZoomAccessConnector) SyncGroupMembers(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	groupExternalID, checkpoint string,
	handler func(memberExternalIDs []string, nextCheckpoint string) error,
) error {
	if strings.TrimSpace(groupExternalID) == "" {
		return errors.New("zoom: group external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	tok, err := c.accessToken(ctx, cfg, secrets)
	if err != nil {
		return err
	}
	page := 1
	if checkpoint != "" {
		if n, err := strconv.Atoi(checkpoint); err == nil && n > 0 {
			page = n
		}
	}
	for {
		path := fmt.Sprintf("/groups/%s/members?page_size=300&page_number=%d",
			url.PathEscape(groupExternalID), page)
		req, err := c.newRequest(ctx, tok, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp zoomGroupMembersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("zoom: decode group members: %w", err)
		}
		ids := make([]string, 0, len(resp.Members))
		for _, m := range resp.Members {
			ids = append(ids, m.ID)
		}
		next := ""
		if resp.PageCount > page {
			next = strconv.Itoa(page + 1)
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

var _ access.GroupSyncer = (*ZoomAccessConnector)(nil)
