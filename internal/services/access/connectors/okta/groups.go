// Package okta — GroupSyncer implementation.
//
// Okta exposes groups under /api/v1/groups (paginated via RFC-5988
// Link rel="next") and per-group members under
// /api/v1/groups/{groupId}/users with the same pagination contract.
// We surface that contract through the access.GroupSyncer optional
// interface so the worker can fan out group/membership sync
// alongside identity sync.
package okta

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// oktaGroup is the minimal projection of the Okta groups payload we
// surface upstream. Only fields needed for the Identity envelope are
// decoded; the rest are dropped to keep the test fixtures readable.
type oktaGroup struct {
	ID      string `json:"id"`
	Profile struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	} `json:"profile"`
}

// oktaGroupMember mirrors the relevant subset of /groups/{id}/users.
// Okta returns full user objects but we only need the external ID
// because the caller correlates the IDs against the identity
// pipeline.
type oktaGroupMember struct {
	ID string `json:"id"`
}

// CountGroups returns the workspace's group count or -1 when the
// header isn't surfaced. Mirrors CountIdentities semantics.
func (c *OktaAccessConnector) CountGroups(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	req, err := c.newRequest(ctx, cfg, secrets, http.MethodGet, "/api/v1/groups?limit=1", nil)
	if err != nil {
		return 0, err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return 0, fmt.Errorf("okta: count groups status %d: %s", resp.StatusCode, string(body))
	}
	if total := resp.Header.Get("X-Total-Count"); total != "" {
		if n, err := strconv.Atoi(total); err == nil {
			return n, nil
		}
	}
	return -1, nil
}

// SyncGroups paginates /api/v1/groups, mapping each group to an
// Identity envelope with Type=group. The checkpoint contract mirrors
// SyncIdentities: an opaque rel="next" URL the caller persists
// between runs so resumption is free.
func (c *OktaAccessConnector) SyncGroups(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	startURL := checkpoint
	if startURL == "" {
		startURL = c.absURL(cfg, "/api/v1/groups?limit=200")
	}
	for next := startURL; next != ""; {
		reqURL := next
		if c.urlOverride != "" {
			reqURL = c.rewriteForTest(reqURL)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "SSWS "+strings.TrimPrefix(secrets.APIToken, "SSWS "))
		req.Header.Set("Accept", "application/json")

		resp, err := c.doRaw(req)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			_ = resp.Body.Close()
			return fmt.Errorf("okta: groups page status %d: %s", resp.StatusCode, string(body))
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return err
		}
		var groups []oktaGroup
		if err := json.Unmarshal(body, &groups); err != nil {
			return fmt.Errorf("okta: decode groups page: %w", err)
		}
		batch := mapOktaGroups(groups)
		nextLink := parseNextLink(resp.Header.Get("Link"))
		if err := handler(batch, nextLink); err != nil {
			return err
		}
		next = nextLink
	}
	return nil
}

// SyncGroupMembers paginates /api/v1/groups/{groupId}/users and
// yields the page's member external IDs. groupExternalID is the
// Okta group ID as surfaced via SyncGroups.
func (c *OktaAccessConnector) SyncGroupMembers(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	groupExternalID, checkpoint string,
	handler func(memberExternalIDs []string, nextCheckpoint string) error,
) error {
	if strings.TrimSpace(groupExternalID) == "" {
		return fmt.Errorf("okta: group external id is required")
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	startURL := checkpoint
	if startURL == "" {
		startURL = c.absURL(cfg, "/api/v1/groups/"+url.PathEscape(groupExternalID)+"/users?limit=200")
	}
	for next := startURL; next != ""; {
		reqURL := next
		if c.urlOverride != "" {
			reqURL = c.rewriteForTest(reqURL)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "SSWS "+strings.TrimPrefix(secrets.APIToken, "SSWS "))
		req.Header.Set("Accept", "application/json")

		resp, err := c.doRaw(req)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			_ = resp.Body.Close()
			return fmt.Errorf("okta: group members page status %d: %s", resp.StatusCode, string(body))
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return err
		}
		var members []oktaGroupMember
		if err := json.Unmarshal(body, &members); err != nil {
			return fmt.Errorf("okta: decode group members: %w", err)
		}
		ids := make([]string, 0, len(members))
		for _, m := range members {
			if m.ID != "" {
				ids = append(ids, m.ID)
			}
		}
		nextLink := parseNextLink(resp.Header.Get("Link"))
		if err := handler(ids, nextLink); err != nil {
			return err
		}
		next = nextLink
	}
	return nil
}

// mapOktaGroups translates the Okta group payload into the
// platform-wide Identity envelope. Type is access.IdentityTypeGroup
// so the worker stores groups in the access_teams table.
func mapOktaGroups(groups []oktaGroup) []*access.Identity {
	out := make([]*access.Identity, 0, len(groups))
	for _, g := range groups {
		out = append(out, &access.Identity{
			ExternalID:  g.ID,
			Type:        access.IdentityTypeGroup,
			DisplayName: g.Profile.Name,
		})
	}
	return out
}
