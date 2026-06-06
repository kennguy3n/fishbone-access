// Package box — GroupSyncer implementation.
//
// Box enterprise groups are listed at GET /2.0/groups using
// offset/limit pagination. Group memberships are listed at
// GET /2.0/groups/{id}/memberships, also offset/limit-paginated.
// The checkpoint is the decimal-encoded next offset.
package box

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

type boxGroup struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type boxGroupsResponse struct {
	TotalCount int        `json:"total_count"`
	Limit      int        `json:"limit"`
	Offset     int        `json:"offset"`
	Entries    []boxGroup `json:"entries"`
}

type boxMembership struct {
	ID   string `json:"id"`
	User struct {
		ID    string `json:"id"`
		Login string `json:"login"`
	} `json:"user"`
}

type boxMembershipsResponse struct {
	TotalCount int             `json:"total_count"`
	Limit      int             `json:"limit"`
	Offset     int             `json:"offset"`
	Entries    []boxMembership `json:"entries"`
}

// CountGroups walks SyncGroups and tallies every page.
func (c *BoxAccessConnector) CountGroups(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	total := 0
	err := c.SyncGroups(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		total += len(b)
		return nil
	})
	return total, err
}

// SyncGroups paginates /2.0/groups using offset/limit.
func (c *BoxAccessConnector) SyncGroups(
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
		if n, err := strconv.Atoi(checkpoint); err == nil && n >= 0 {
			offset = n
		}
	}
	base := c.baseURL()
	for pageCount := 0; pageCount < boxSyncMaxPages; pageCount++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		path := fmt.Sprintf("%s/2.0/groups?limit=%d&offset=%d", base, pageSize, offset)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp boxGroupsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("box: decode groups: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Entries))
		for _, g := range resp.Entries {
			identities = append(identities, &access.Identity{
				ExternalID:  g.ID,
				Type:        access.IdentityTypeGroup,
				DisplayName: g.Name,
				Status:      "active",
			})
		}
		next := ""
		if offset+len(resp.Entries) < resp.TotalCount && len(resp.Entries) > 0 {
			next = strconv.Itoa(offset + pageSize)
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		offset += pageSize
	}
	// Defensive page cap reached; the last handler call carried a
	// non-empty checkpoint, so the next sync cycle resumes from there.
	return nil
}

// SyncGroupMembers paginates /2.0/groups/{id}/memberships and emits
// the embedded user.id for each membership entry.
func (c *BoxAccessConnector) SyncGroupMembers(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	groupExternalID, checkpoint string,
	handler func(memberExternalIDs []string, nextCheckpoint string) error,
) error {
	if strings.TrimSpace(groupExternalID) == "" {
		return errors.New("box: group external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	offset := 0
	if checkpoint != "" {
		if n, err := strconv.Atoi(checkpoint); err == nil && n >= 0 {
			offset = n
		}
	}
	base := c.baseURL()
	for pageCount := 0; pageCount < boxSyncMaxPages; pageCount++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		path := fmt.Sprintf("%s/2.0/groups/%s/memberships?limit=%d&offset=%d",
			base, url.PathEscape(groupExternalID), pageSize, offset)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp boxMembershipsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("box: decode memberships: %w", err)
		}
		ids := make([]string, 0, len(resp.Entries))
		for _, m := range resp.Entries {
			if m.User.ID != "" {
				ids = append(ids, m.User.ID)
			}
		}
		next := ""
		if offset+len(resp.Entries) < resp.TotalCount && len(resp.Entries) > 0 {
			next = strconv.Itoa(offset + pageSize)
		}
		if err := handler(ids, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		offset += pageSize
	}
	// Defensive page cap reached; the last handler call carried a
	// non-empty checkpoint, so the next sync cycle resumes from there.
	return nil
}

var _ access.GroupSyncer = (*BoxAccessConnector)(nil)
