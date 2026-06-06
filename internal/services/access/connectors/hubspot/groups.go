// Package hubspot — GroupSyncer implementation.
//
// HubSpot models access groups as "teams" under /settings/v3/users/teams.
// The roster endpoint returns the entire team list (no pagination); each
// team includes a nested `userIds` slice that we project through
// SyncGroupMembers without a second round-trip.
package hubspot

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type hubspotTeam struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	UserIds          []string `json:"userIds"`
	SecondaryUserIds []string `json:"secondaryUserIds,omitempty"`
}

type hubspotTeamsResponse struct {
	Results []hubspotTeam `json:"results"`
}

// CountGroups streams SyncGroups and tallies the batch.
func (c *HubSpotAccessConnector) CountGroups(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	total := 0
	err := c.SyncGroups(ctx, configRaw, secretsRaw, "", func(batch []*access.Identity, _ string) error {
		total += len(batch)
		return nil
	})
	return total, err
}

// SyncGroups returns every HubSpot team in a single batch. HubSpot's
// public API does not paginate the teams collection (team counts are
// small by design), so the handler is invoked once with all teams.
func (c *HubSpotAccessConnector) SyncGroups(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	_ string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, "/settings/v3/users/teams")
	if err != nil {
		return err
	}
	body, err := c.do(req)
	if err != nil {
		return err
	}
	var resp hubspotTeamsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("hubspot: decode teams: %w", err)
	}
	groups := make([]*access.Identity, 0, len(resp.Results))
	for _, t := range resp.Results {
		display := strings.TrimSpace(t.Name)
		if display == "" {
			display = t.ID
		}
		groups = append(groups, &access.Identity{
			ExternalID:  t.ID,
			Type:        access.IdentityTypeGroup,
			DisplayName: display,
			Status:      "active",
		})
	}
	return handler(groups, "")
}

// SyncGroupMembers fetches a single team by ID and reports its
// `userIds` + `secondaryUserIds` slices as a single batch.
func (c *HubSpotAccessConnector) SyncGroupMembers(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	groupExternalID, _ string,
	handler func(memberExternalIDs []string, nextCheckpoint string) error,
) error {
	if strings.TrimSpace(groupExternalID) == "" {
		return fmt.Errorf("hubspot: group external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	path := "/settings/v3/users/teams/" + url.PathEscape(groupExternalID)
	req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
	if err != nil {
		return err
	}
	body, err := c.do(req)
	if err != nil {
		return err
	}
	var team hubspotTeam
	if err := json.Unmarshal(body, &team); err != nil {
		return fmt.Errorf("hubspot: decode team: %w", err)
	}
	out := make([]string, 0, len(team.UserIds)+len(team.SecondaryUserIds))
	for _, uid := range team.UserIds {
		if s := strings.TrimSpace(uid); s != "" {
			out = append(out, s)
		}
	}
	for _, uid := range team.SecondaryUserIds {
		if s := strings.TrimSpace(uid); s != "" {
			out = append(out, s)
		}
	}
	return handler(out, "")
}

var _ access.GroupSyncer = (*HubSpotAccessConnector)(nil)
