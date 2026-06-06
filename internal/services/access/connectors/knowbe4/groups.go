// Package knowbe4 — GroupSyncer implementation.
//
// KnowBe4 models user collections as Groups at /v1/groups (page-based
// pagination identical to the /v1/users SyncIdentities path). Group
// members are returned by GET /v1/groups/{group_id}/members — also
// paginated.
package knowbe4

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

type knowbe4Group struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Status      string `json:"status"`
	GroupType   string `json:"group_type"`
	MemberCount int    `json:"member_count"`
}

type knowbe4GroupMember struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
}

// CountGroups walks SyncGroups and tallies every page.
func (c *KnowBe4AccessConnector) CountGroups(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	total := 0
	err := c.SyncGroups(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		total += len(b)
		return nil
	})
	return total, err
}

// SyncGroups paginates /v1/groups using the same page-based scheme
// as /v1/users SyncIdentities. Each Identity is type
// IdentityTypeGroup with ExternalID set to the numeric group id.
func (c *KnowBe4AccessConnector) SyncGroups(
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
		if p, err := strconv.Atoi(checkpoint); err == nil && p > 0 {
			page = p
		}
	}
	base := c.baseURL(cfg)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		path := fmt.Sprintf("%s/v1/groups?page=%d&per_page=%d", base, page, pageSize)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var groups []knowbe4Group
		if err := json.Unmarshal(body, &groups); err != nil {
			return fmt.Errorf("knowbe4: decode groups: %w", err)
		}
		identities := make([]*access.Identity, 0, len(groups))
		for _, g := range groups {
			display := g.Name
			if display == "" {
				display = strconv.Itoa(g.ID)
			}
			status := "active"
			if g.Status != "" && g.Status != "active" {
				status = g.Status
			}
			identities = append(identities, &access.Identity{
				ExternalID:  strconv.Itoa(g.ID),
				Type:        access.IdentityTypeGroup,
				DisplayName: display,
				Status:      status,
			})
		}
		next := ""
		if len(groups) >= pageSize {
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

// SyncGroupMembers paginates /v1/groups/{id}/members and emits the
// numeric user IDs assigned to the group. groupExternalID must be
// the numeric group id surfaced by SyncGroups.
func (c *KnowBe4AccessConnector) SyncGroupMembers(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	groupExternalID, checkpoint string,
	handler func(memberExternalIDs []string, nextCheckpoint string) error,
) error {
	if groupExternalID == "" {
		return errors.New("knowbe4: group external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	page := 1
	if checkpoint != "" {
		if p, err := strconv.Atoi(checkpoint); err == nil && p > 0 {
			page = p
		}
	}
	base := c.baseURL(cfg)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		path := fmt.Sprintf("%s/v1/groups/%s/members?page=%d&per_page=%d",
			base, url.PathEscape(groupExternalID), page, pageSize)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var members []knowbe4GroupMember
		if err := json.Unmarshal(body, &members); err != nil {
			return fmt.Errorf("knowbe4: decode group members: %w", err)
		}
		ids := make([]string, 0, len(members))
		for _, m := range members {
			ids = append(ids, strconv.Itoa(m.ID))
		}
		next := ""
		if len(members) >= pageSize {
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

var _ access.GroupSyncer = (*KnowBe4AccessConnector)(nil)
