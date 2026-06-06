// Package gitlab — GroupSyncer implementation.
//
// GitLab models nested groups as subgroups of a parent group. We page
// /api/v4/groups/{id}/subgroups and emit each subgroup as a group
// Identity, and page /api/v4/groups/{id}/members to enumerate the
// direct members of a given (sub)group. Both endpoints use page-number
// pagination with the X-Next-Page response header indicating the next
// page when more remain.
package gitlab

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

type gitlabSubgroup struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	FullPath string `json:"full_path"`
}

// CountGroups walks SyncGroups and tallies every page.
func (c *GitLabAccessConnector) CountGroups(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	total := 0
	err := c.SyncGroups(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		total += len(b)
		return nil
	})
	return total, err
}

// SyncGroups paginates /api/v4/groups/{id}/subgroups. Each subgroup
// becomes a group Identity envelope keyed by its integer ID.
func (c *GitLabAccessConnector) SyncGroups(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	page := 1
	if checkpoint != "" {
		if n, err := strconv.Atoi(checkpoint); err == nil && n > 0 {
			page = n
		}
	}
	base := c.baseURL(cfg)
	for {
		path := fmt.Sprintf("%s/api/v4/groups/%s/subgroups?per_page=100&page=%d", base, url.PathEscape(cfg.GroupID), page)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		resp, err := c.doRaw(req)
		if err != nil {
			return err
		}
		var subs []gitlabSubgroup
		if err := json.Unmarshal(resp.Body, &subs); err != nil {
			return fmt.Errorf("gitlab: decode subgroups: %w", err)
		}
		identities := make([]*access.Identity, 0, len(subs))
		for _, s := range subs {
			name := s.Name
			if name == "" {
				name = s.FullPath
			}
			identities = append(identities, &access.Identity{
				ExternalID:  strconv.Itoa(s.ID),
				Type:        access.IdentityTypeGroup,
				DisplayName: name,
				Status:      "active",
			})
		}
		next := strings.TrimSpace(resp.Header.Get("X-Next-Page"))
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		page++
	}
}

// SyncGroupMembers paginates /api/v4/groups/{id}/members and emits
// each member's integer ID as the external ID.
func (c *GitLabAccessConnector) SyncGroupMembers(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	groupExternalID, checkpoint string,
	handler func(memberExternalIDs []string, nextCheckpoint string) error,
) error {
	if strings.TrimSpace(groupExternalID) == "" {
		return errors.New("gitlab: group external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	page := 1
	if checkpoint != "" {
		if n, err := strconv.Atoi(checkpoint); err == nil && n > 0 {
			page = n
		}
	}
	base := c.baseURL(cfg)
	for {
		path := fmt.Sprintf("%s/api/v4/groups/%s/members?per_page=100&page=%d", base, url.PathEscape(groupExternalID), page)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		resp, err := c.doRaw(req)
		if err != nil {
			return err
		}
		var members []gitlabMember
		if err := json.Unmarshal(resp.Body, &members); err != nil {
			return fmt.Errorf("gitlab: decode members: %w", err)
		}
		ids := make([]string, 0, len(members))
		for _, m := range members {
			ids = append(ids, strconv.Itoa(m.ID))
		}
		next := strings.TrimSpace(resp.Header.Get("X-Next-Page"))
		if err := handler(ids, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		page++
	}
}

var _ access.GroupSyncer = (*GitLabAccessConnector)(nil)
