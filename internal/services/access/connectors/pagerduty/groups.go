// Package pagerduty — GroupSyncer implementation.
//
// PagerDuty models groups as teams. /teams paginates via the standard
// offset/limit + more=true pattern shared with /users, and team
// membership is exposed via /teams/{id}/members. The checkpoint is
// the decimal-encoded next offset.
package pagerduty

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

type pagerdutyTeam struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type pagerdutyTeamsResponse struct {
	Teams  []pagerdutyTeam `json:"teams"`
	Limit  int             `json:"limit"`
	Offset int             `json:"offset"`
	More   bool            `json:"more"`
}

type pagerdutyTeamMember struct {
	User struct {
		ID string `json:"id"`
	} `json:"user"`
	Role string `json:"role"`
}

type pagerdutyTeamMembersResponse struct {
	Members []pagerdutyTeamMember `json:"members"`
	Limit   int                   `json:"limit"`
	Offset  int                   `json:"offset"`
	More    bool                  `json:"more"`
}

// CountGroups walks SyncGroups and tallies every page.
func (c *PagerDutyAccessConnector) CountGroups(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	total := 0
	err := c.SyncGroups(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		total += len(b)
		return nil
	})
	return total, err
}

// SyncGroups paginates /teams using offset/limit.
func (c *PagerDutyAccessConnector) SyncGroups(
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
	for {
		path := fmt.Sprintf("/teams?limit=%d&offset=%d", pageLimit, offset)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp pagerdutyTeamsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("pagerduty: decode teams: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Teams))
		for _, tm := range resp.Teams {
			identities = append(identities, &access.Identity{
				ExternalID:  tm.ID,
				Type:        access.IdentityTypeGroup,
				DisplayName: tm.Name,
				Status:      "active",
			})
		}
		next := ""
		if resp.More {
			next = strconv.Itoa(offset + len(resp.Teams))
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		offset += len(resp.Teams)
	}
}

// SyncGroupMembers paginates /teams/{id}/members and emits the
// embedded user.id for each member entry.
func (c *PagerDutyAccessConnector) SyncGroupMembers(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	groupExternalID, checkpoint string,
	handler func(memberExternalIDs []string, nextCheckpoint string) error,
) error {
	if strings.TrimSpace(groupExternalID) == "" {
		return errors.New("pagerduty: group external id is required")
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
	for {
		path := fmt.Sprintf("/teams/%s/members?limit=%d&offset=%d",
			url.PathEscape(groupExternalID), pageLimit, offset)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp pagerdutyTeamMembersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("pagerduty: decode team members: %w", err)
		}
		ids := make([]string, 0, len(resp.Members))
		for _, m := range resp.Members {
			if m.User.ID != "" {
				ids = append(ids, m.User.ID)
			}
		}
		next := ""
		if resp.More {
			next = strconv.Itoa(offset + len(resp.Members))
		}
		if err := handler(ids, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		offset += len(resp.Members)
	}
}

var _ access.GroupSyncer = (*PagerDutyAccessConnector)(nil)
