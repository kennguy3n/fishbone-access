// Package front — GroupSyncer over the Front /teams API.
//
// Front models access groups as "Teams". The public REST API
// exposes:
//
//	GET /teams                          paginated via _pagination.next
//	GET /teams/{team_id}                team detail (id, name)
//	GET /teams/{team_id}/teammates      paginated via _pagination.next
//
// Pagination follows Front's standard `_pagination.next` envelope —
// an absolute URL the client follows verbatim. ExternalID is the
// Front team id (a stable string). Membership is the teammate id
// (Front's stable teammate identifier).
package front

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

// CountGroups walks every page of /teams and returns the cumulative
// count. Front does not surface a top-level count field on the
// teams listing endpoint, so we walk every page.
func (c *FrontAccessConnector) CountGroups(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	next := c.baseURL() + "/teams"
	total := 0
	for next != "" {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, next)
		if err != nil {
			return 0, err
		}
		body, err := c.do(req)
		if err != nil {
			return 0, err
		}
		var page frontTeamsResponse
		if err := json.Unmarshal(body, &page); err != nil {
			return 0, fmt.Errorf("front: decode teams: %w", err)
		}
		total += len(page.Results)
		next = strings.TrimSpace(page.Pagination.Next)
	}
	return total, nil
}

// SyncGroups paginates /teams via the absolute `_pagination.next`
// URL the upstream returns. ExternalID is the team id; DisplayName
// is the team name.
func (c *FrontAccessConnector) SyncGroups(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	next := checkpoint
	if next == "" {
		next = c.baseURL() + "/teams"
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, next)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var page frontTeamsResponse
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("front: decode teams: %w", err)
		}
		identities := make([]*access.Identity, 0, len(page.Results))
		for _, tm := range page.Results {
			identities = append(identities, &access.Identity{
				ExternalID:  tm.ID,
				Type:        access.IdentityTypeGroup,
				DisplayName: tm.Name,
				Status:      "active",
			})
		}
		nextCursor := strings.TrimSpace(page.Pagination.Next)
		if err := handler(identities, nextCursor); err != nil {
			return err
		}
		if nextCursor == "" {
			return nil
		}
		next = nextCursor
	}
}

// SyncGroupMembers paginates /teams/{team_id}/teammates and emits
// every teammate id as a member external id. 404 on the team
// endpoint maps to an empty membership (team already gone — leaver
// flow contract).
func (c *FrontAccessConnector) SyncGroupMembers(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	groupExternalID, checkpoint string,
	handler func(memberExternalIDs []string, nextCheckpoint string) error,
) error {
	groupExternalID = strings.TrimSpace(groupExternalID)
	if groupExternalID == "" {
		return errors.New("front: sync group members: groupExternalID is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	next := checkpoint
	if next == "" {
		next = c.baseURL() + "/teams/" + url.PathEscape(groupExternalID) + "/teammates"
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, next)
		if err != nil {
			return err
		}
		body, found, err := c.do2xxOr404(req)
		if err != nil {
			return err
		}
		if !found {
			// Non-nil empty slice per GroupSyncer empty-batch
			// contract — see optional_interfaces.go.
			return handler([]string{}, "")
		}
		var page frontListResponse
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("front: decode team teammates: %w", err)
		}
		ids := make([]string, 0, len(page.Results))
		for _, m := range page.Results {
			if m.ID == "" {
				continue
			}
			ids = append(ids, m.ID)
		}
		nextCursor := strings.TrimSpace(page.Pagination.Next)
		if err := handler(ids, nextCursor); err != nil {
			return err
		}
		if nextCursor == "" {
			return nil
		}
		next = nextCursor
	}
}

var _ access.GroupSyncer = (*FrontAccessConnector)(nil)
