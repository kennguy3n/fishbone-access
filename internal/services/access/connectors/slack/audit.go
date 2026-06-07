package slack

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const slackAuditBaseURL = "https://api.slack.com"

// slackAuditMaxPages bounds the audit-log pagination loop so a never-empty
// next_cursor (API bug/change) cannot drive unbounded HTTP requests, matching
// the safety guard used by the other audit connectors in this batch.
const slackAuditMaxPages = 200

// FetchAccessAuditLogs streams Slack Enterprise Grid audit log events
// into the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /audit/v1/logs?oldest={unix_since}&limit=200&cursor=...
//
// Pagination uses Slack's response_metadata.next_cursor. Workspaces
// that are not on Enterprise Grid receive a `not_authorized` or
// `team_not_eligible` API error; we collapse those to
// access.ErrAuditNotAvailable so the caller can soft-skip.
func (c *SlackAccessConnector) FetchAccessAuditLogs(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	sincePartitions map[string]time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}

	since := sincePartitions[access.DefaultAuditPartition]
	cursor := since
	pageCursor := ""
	for pageNum := 0; pageNum < slackAuditMaxPages; pageNum++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", "200")
		if !since.IsZero() {
			q.Set("oldest", fmt.Sprintf("%d", since.Unix()))
		}
		if pageCursor != "" {
			q.Set("cursor", pageCursor)
		}
		endpoint := c.auditURL("/audit/v1/logs?" + q.Encode())
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.BotToken))
		body, apiErr, err := c.doWithAPIError(req)
		if err != nil {
			return err
		}
		if apiErr != "" {
			switch apiErr {
			case "not_authorized", "team_not_eligible", "not_an_enterprise":
				return access.ErrAuditNotAvailable
			default:
				return fmt.Errorf("slack: audit logs: api error: %s", apiErr)
			}
		}
		var page slackAuditPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("slack: decode audit page: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Entries))
		batchMax := cursor
		for i := range page.Entries {
			entry := mapSlackAuditEntry(&page.Entries[i])
			if entry == nil {
				continue
			}
			if entry.Timestamp.After(batchMax) {
				batchMax = entry.Timestamp
			}
			batch = append(batch, entry)
		}
		if err := handler(batch, batchMax, access.DefaultAuditPartition); err != nil {
			return err
		}
		cursor = batchMax
		next := strings.TrimSpace(page.ResponseMetadata.NextCursor)
		if next == "" {
			return nil
		}
		pageCursor = next
	}
	// Page budget exhausted while Slack still reports more pages; stop
	// rather than loop unbounded.
	return nil
}

func (c *SlackAccessConnector) auditURL(path string) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/") + path
	}
	return slackAuditBaseURL + path
}

type slackAuditPage struct {
	OK               bool                 `json:"ok"`
	Entries          []slackAuditEntry    `json:"entries"`
	ResponseMetadata slackAuditPageCursor `json:"response_metadata"`
}

type slackAuditPageCursor struct {
	NextCursor string `json:"next_cursor"`
}

type slackAuditEntry struct {
	ID         string `json:"id"`
	DateCreate int64  `json:"date_create"`
	Action     string `json:"action"`
	Actor      struct {
		Type string `json:"type"`
		User struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			Email string `json:"email"`
		} `json:"user"`
	} `json:"actor"`
	Entity struct {
		Type string `json:"type"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		Workspace struct {
			ID string `json:"id"`
		} `json:"workspace"`
		Channel struct {
			ID string `json:"id"`
		} `json:"channel"`
	} `json:"entity"`
	Context struct {
		IPAddress string `json:"ip_address"`
		UserAgent string `json:"ua"`
	} `json:"context"`
}

func mapSlackAuditEntry(e *slackAuditEntry) *access.AuditLogEntry {
	if e == nil || e.ID == "" {
		return nil
	}
	var targetID, targetType string
	switch e.Entity.Type {
	case "user":
		targetID = e.Entity.User.ID
		targetType = "user"
	case "workspace":
		targetID = e.Entity.Workspace.ID
		targetType = "workspace"
	case "channel":
		targetID = e.Entity.Channel.ID
		targetType = "channel"
	}
	if e.DateCreate <= 0 {
		return nil
	}
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        e.Action,
		Action:           e.Action,
		Timestamp:        time.Unix(e.DateCreate, 0).UTC(),
		ActorExternalID:  e.Actor.User.ID,
		ActorEmail:       e.Actor.User.Email,
		TargetExternalID: targetID,
		TargetType:       targetType,
		IPAddress:        e.Context.IPAddress,
		UserAgent:        e.Context.UserAgent,
		Outcome:          "success",
	}
}

var _ access.AccessAuditor = (*SlackAccessConnector)(nil)
