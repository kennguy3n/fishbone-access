// Package jira — GroupSyncer implementation.
//
// Atlassian Jira models groups via /rest/api/3/group/bulk (the
// roster) and /rest/api/3/group/member?groupId={id} (per-group
// membership). Both endpoints use startAt/maxResults pagination
// and surface an `isLast` flag plus a `nextPage` URL.
package jira

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

type jiraGroupRow struct {
	GroupID string `json:"groupId"`
	Name    string `json:"name"`
}

type jiraGroupBulkResponse struct {
	Values     []jiraGroupRow `json:"values"`
	IsLast     bool           `json:"isLast"`
	StartAt    int            `json:"startAt"`
	MaxResults int            `json:"maxResults"`
	Total      int            `json:"total"`
}

type jiraGroupMemberRow struct {
	AccountID   string `json:"accountId"`
	DisplayName string `json:"displayName"`
}

type jiraGroupMemberResponse struct {
	Values     []jiraGroupMemberRow `json:"values"`
	IsLast     bool                 `json:"isLast"`
	StartAt    int                  `json:"startAt"`
	MaxResults int                  `json:"maxResults"`
	Total      int                  `json:"total"`
}

// CountGroups walks SyncGroups and tallies every batch.
func (c *JiraAccessConnector) CountGroups(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	total := 0
	err := c.SyncGroups(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		total += len(b)
		return nil
	})
	return total, err
}

// SyncGroups paginates /rest/api/3/group/bulk using
// startAt/maxResults. The checkpoint is the next startAt encoded
// as a decimal string.
func (c *JiraAccessConnector) SyncGroups(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	startAt := 0
	if checkpoint != "" {
		if n, err := strconv.Atoi(checkpoint); err == nil {
			startAt = n
		}
	}
	for {
		urlStr := fmt.Sprintf("%s/rest/api/3/group/bulk?startAt=%d&maxResults=%d",
			c.baseURL(cfg), startAt, pageSize)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, urlStr)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp jiraGroupBulkResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("jira: decode group bulk: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Values))
		for _, g := range resp.Values {
			identities = append(identities, &access.Identity{
				ExternalID:  g.GroupID,
				Type:        access.IdentityTypeGroup,
				DisplayName: g.Name,
				Status:      "active",
			})
		}
		nextCheckpoint := ""
		if !resp.IsLast && len(resp.Values) > 0 {
			nextCheckpoint = strconv.Itoa(startAt + len(resp.Values))
		}
		if err := handler(identities, nextCheckpoint); err != nil {
			return err
		}
		if nextCheckpoint == "" {
			return nil
		}
		startAt += len(resp.Values)
	}
}

// SyncGroupMembers paginates /rest/api/3/group/member?groupId={id}
// using the same startAt/maxResults shape.
func (c *JiraAccessConnector) SyncGroupMembers(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	groupExternalID, checkpoint string,
	handler func(memberExternalIDs []string, nextCheckpoint string) error,
) error {
	if strings.TrimSpace(groupExternalID) == "" {
		return errors.New("jira: group external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	startAt := 0
	if checkpoint != "" {
		if n, err := strconv.Atoi(checkpoint); err == nil {
			startAt = n
		}
	}
	for {
		urlStr := fmt.Sprintf("%s/rest/api/3/group/member?groupId=%s&startAt=%d&maxResults=%d",
			c.baseURL(cfg), url.QueryEscape(groupExternalID), startAt, pageSize)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, urlStr)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp jiraGroupMemberResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("jira: decode group members: %w", err)
		}
		ids := make([]string, 0, len(resp.Values))
		for _, m := range resp.Values {
			ids = append(ids, m.AccountID)
		}
		nextCheckpoint := ""
		if !resp.IsLast && len(resp.Values) > 0 {
			nextCheckpoint = strconv.Itoa(startAt + len(resp.Values))
		}
		if err := handler(ids, nextCheckpoint); err != nil {
			return err
		}
		if nextCheckpoint == "" {
			return nil
		}
		startAt += len(resp.Values)
	}
}

var _ access.GroupSyncer = (*JiraAccessConnector)(nil)
