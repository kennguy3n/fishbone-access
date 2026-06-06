// Package auth0 — GroupSyncer implementation.
//
// Auth0 models "groups" as Organizations. /api/v2/organizations
// returns the org roster (page-number paginated, like /users) and
// /api/v2/organizations/{id}/members returns the per-org membership
// (checkpoint-based pagination via a "next" link in the response
// when more pages are available).
package auth0

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

type auth0Organization struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
}

type auth0OrganizationMember struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
}

type auth0OrgMembersPage struct {
	Members []auth0OrganizationMember `json:"members"`
	Next    string                    `json:"next"`
}

// CountGroups walks SyncGroups and tallies every page. Auth0
// exposes include_totals=true on /organizations but the marginal
// API cost is small enough that the streaming shape stays uniform
// with the other GroupSyncer connectors.
func (c *Auth0AccessConnector) CountGroups(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	total := 0
	err := c.SyncGroups(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		total += len(b)
		return nil
	})
	return total, err
}

// SyncGroups pages through /api/v2/organizations using the same
// page-number scheme as SyncIdentities. Each org becomes an Identity
// envelope with ExternalID = org.id.
func (c *Auth0AccessConnector) SyncGroups(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	token, err := c.fetchAccessToken(ctx, cfg, secrets)
	if err != nil {
		return fmt.Errorf("auth0: authenticate: %w", err)
	}

	page := 0
	if checkpoint != "" {
		if n, err := strconv.Atoi(checkpoint); err == nil {
			page = n
		}
	}
	const perPage = 100

	for {
		path := fmt.Sprintf("/api/v2/organizations?per_page=%d&page=%d", perPage, page)
		req, err := c.newAuthedRequest(ctx, cfg, token, http.MethodGet, path, nil)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var orgs []auth0Organization
		if err := json.Unmarshal(body, &orgs); err != nil {
			return fmt.Errorf("auth0: decode organizations: %w", err)
		}

		identities := make([]*access.Identity, 0, len(orgs))
		for _, o := range orgs {
			name := o.DisplayName
			if name == "" {
				name = o.Name
			}
			identities = append(identities, &access.Identity{
				ExternalID:  o.ID,
				Type:        access.IdentityTypeGroup,
				DisplayName: name,
				Status:      "active",
			})
		}
		nextCheckpoint := ""
		if len(orgs) == perPage {
			nextCheckpoint = strconv.Itoa(page + 1)
		}
		if err := handler(identities, nextCheckpoint); err != nil {
			return err
		}
		if nextCheckpoint == "" {
			return nil
		}
		page++
	}
}

// SyncGroupMembers pages through /api/v2/organizations/{id}/members.
// Auth0 uses checkpoint-based pagination (a `from` query parameter
// keyed off the page's last user_id), and surfaces the next-page
// token as the `next` field in the response body.
func (c *Auth0AccessConnector) SyncGroupMembers(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	groupExternalID, checkpoint string,
	handler func(memberExternalIDs []string, nextCheckpoint string) error,
) error {
	if strings.TrimSpace(groupExternalID) == "" {
		return errors.New("auth0: group external id is required")
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	token, err := c.fetchAccessToken(ctx, cfg, secrets)
	if err != nil {
		return fmt.Errorf("auth0: authenticate: %w", err)
	}

	from := checkpoint
	const take = 100

	for {
		path := fmt.Sprintf("/api/v2/organizations/%s/members?take=%d&include_totals=true",
			url.PathEscape(groupExternalID), take)
		if from != "" {
			path += "&from=" + url.QueryEscape(from)
		}
		req, err := c.newAuthedRequest(ctx, cfg, token, http.MethodGet, path, nil)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var page auth0OrgMembersPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("auth0: decode org members: %w", err)
		}

		ids := make([]string, 0, len(page.Members))
		for _, m := range page.Members {
			ids = append(ids, m.UserID)
		}
		nextCheckpoint := page.Next
		if err := handler(ids, nextCheckpoint); err != nil {
			return err
		}
		if nextCheckpoint == "" {
			return nil
		}
		from = nextCheckpoint
	}
}

var _ access.GroupSyncer = (*Auth0AccessConnector)(nil)
