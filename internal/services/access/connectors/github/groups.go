// Package github — GroupSyncer implementation.
//
// GitHub models org-level "groups" as Teams. /orgs/{org}/teams
// returns the team roster, and /orgs/{org}/teams/{team_slug}/members
// dumps each team's membership. Both endpoints use the same RFC-5988
// Link rel="next" pagination as /members.
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type githubTeam struct {
	ID          int64  `json:"id"`
	NodeID      string `json:"node_id"`
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Privacy     string `json:"privacy"`
}

type githubTeamMember struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Type  string `json:"type"`
}

// CountGroups streams SyncGroups and tallies every batch. GitHub
// doesn't expose a count probe so this is the cheapest correct
// shape (same pattern as CountIdentities).
func (c *GitHubAccessConnector) CountGroups(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	total := 0
	err := c.SyncGroups(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		total += len(b)
		return nil
	})
	return total, err
}

// SyncGroups paginates /orgs/{org}/teams with the RFC-5988 Link
// header rel="next". Each team becomes an Identity envelope with
// ExternalID = numeric team ID (stable across renames; the slug
// changes when the display name changes).
func (c *GitHubAccessConnector) SyncGroups(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	nextURL := checkpoint
	if nextURL == "" {
		nextURL = c.baseURL() + "/orgs/" + url.PathEscape(cfg.Organization) + "/teams?per_page=100"
	}
	for {
		req, err := c.newRequest(ctx, secrets, http.MethodGet, nextURL)
		if err != nil {
			return err
		}
		resp, err := c.doRaw(req)
		if err != nil {
			return err
		}
		var teams []githubTeam
		if err := json.Unmarshal(resp.Body, &teams); err != nil {
			return fmt.Errorf("github: decode teams: %w", err)
		}
		identities := make([]*access.Identity, 0, len(teams))
		for _, t := range teams {
			identities = append(identities, &access.Identity{
				ExternalID:  fmt.Sprintf("%d", t.ID),
				Type:        access.IdentityTypeGroup,
				DisplayName: t.Name,
				Status:      "active",
			})
		}
		next := parseNextLink(resp.Header.Get("Link"))
		if next != "" && c.urlOverride != "" {
			next = strings.Replace(next, defaultBaseURL, strings.TrimRight(c.urlOverride, "/"), 1)
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		nextURL = next
	}
}

// SyncGroupMembers paginates /orgs/{org}/teams/{team_slug}/members.
// GitHub's REST API requires the team slug, but the platform tracks
// teams by numeric ID — we accept either form and resolve the slug
// via /teams/{id} when an all-digit ID is passed.
func (c *GitHubAccessConnector) SyncGroupMembers(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	groupExternalID, checkpoint string,
	handler func(memberExternalIDs []string, nextCheckpoint string) error,
) error {
	if strings.TrimSpace(groupExternalID) == "" {
		return fmt.Errorf("github: group external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}

	nextURL := checkpoint
	if nextURL == "" {
		// Slug resolution is only needed when constructing the first
		// page URL. Resuming via checkpoint already carries the slug
		// in the URL, so skipping the lookup here avoids a wasted
		// HTTP call (and avoids failing the entire resume if the
		// team has since been renamed or deleted).
		slug, err := c.resolveTeamSlug(ctx, secrets, cfg.Organization, groupExternalID)
		if err != nil {
			return err
		}
		nextURL = fmt.Sprintf("%s/orgs/%s/teams/%s/members?per_page=100",
			c.baseURL(), url.PathEscape(cfg.Organization), url.PathEscape(slug))
	}
	for {
		req, err := c.newRequest(ctx, secrets, http.MethodGet, nextURL)
		if err != nil {
			return err
		}
		resp, err := c.doRaw(req)
		if err != nil {
			return err
		}
		var members []githubTeamMember
		if err := json.Unmarshal(resp.Body, &members); err != nil {
			return fmt.Errorf("github: decode team members: %w", err)
		}
		ids := make([]string, 0, len(members))
		for _, m := range members {
			ids = append(ids, fmt.Sprintf("%d", m.ID))
		}
		next := parseNextLink(resp.Header.Get("Link"))
		if next != "" && c.urlOverride != "" {
			next = strings.Replace(next, defaultBaseURL, strings.TrimRight(c.urlOverride, "/"), 1)
		}
		if err := handler(ids, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		nextURL = next
	}
}

// resolveTeamSlug returns the team slug for the given external ID.
// All-digit IDs are dereferenced via the legacy /teams/{team_id}
// endpoint; non-numeric IDs pass through (already a slug).
func (c *GitHubAccessConnector) resolveTeamSlug(ctx context.Context, secrets Secrets, _, externalID string) (string, error) {
	if !isAllDigits(externalID) {
		return externalID, nil
	}
	urlStr := fmt.Sprintf("%s/teams/%s",
		c.baseURL(), url.PathEscape(externalID))
	req, err := c.newRequest(ctx, secrets, http.MethodGet, urlStr)
	if err != nil {
		return "", err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return "", err
	}
	var t githubTeam
	if err := json.Unmarshal(resp.Body, &t); err != nil {
		return "", fmt.Errorf("github: decode team: %w", err)
	}
	if t.Slug == "" {
		return "", fmt.Errorf("github: team %s has no slug", externalID)
	}
	return t.Slug, nil
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
