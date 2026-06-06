package gitlab

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

// FetchAccessAuditLogs streams GitLab group audit events into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /api/v4/groups/{group_id}/audit_events?created_after={since}
//	    &page={n}&per_page=100
//
// GitLab paginates by page/per_page; subsequent pages are signalled by
// the `X-Next-Page` response header (empty/zero terminates). The handler
// is called once per provider page in chronological order so callers
// can persist the monotonic `nextSince` cursor between runs.
//
// 403 Forbidden / 404 Not Found from this endpoint (e.g. the token
// lacks audit_events scope, or the group is on a tier that doesn't
// expose audit events) collapse to access.ErrAuditNotAvailable so the
// worker soft-skips the tenant instead of looping forever.
func (c *GitLabAccessConnector) FetchAccessAuditLogs(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	sincePartitions map[string]time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	since := sincePartitions[access.DefaultAuditPartition]
	cursor := since
	page := 1
	base := c.baseURL(cfg)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("per_page", "100")
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("sort", "asc")
		if !since.IsZero() {
			q.Set("created_after", since.UTC().Format(time.RFC3339))
		}
		fullURL := fmt.Sprintf("%s/api/v4/groups/%s/audit_events?%s", base, url.PathEscape(cfg.GroupID), q.Encode())
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return err
		}
		resp, doErr := c.doRaw(req)
		if resp != nil && (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound) {
			return access.ErrAuditNotAvailable
		}
		if doErr != nil {
			return doErr
		}
		var events []gitlabAuditEvent
		if err := json.Unmarshal(resp.Body, &events); err != nil {
			return fmt.Errorf("gitlab: decode audit page: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(events))
		batchMax := cursor
		for i := range events {
			entry := mapGitlabAuditEvent(&events[i])
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
		next := strings.TrimSpace(resp.Header.Get("X-Next-Page"))
		if next == "" {
			return nil
		}
		page++
	}
}

type gitlabAuditEvent struct {
	ID         int64           `json:"id"`
	AuthorID   int64           `json:"author_id"`
	AuthorName string          `json:"author_name,omitempty"`
	EntityID   int64           `json:"entity_id"`
	EntityType string          `json:"entity_type"`
	CreatedAt  string          `json:"created_at"`
	Details    json.RawMessage `json:"details"`
}

type gitlabAuditDetails struct {
	EventName     string `json:"event_name,omitempty"`
	CustomMessage string `json:"custom_message,omitempty"`
	TargetID      any    `json:"target_id,omitempty"`
	TargetType    string `json:"target_type,omitempty"`
	TargetDetails string `json:"target_details,omitempty"`
	AuthorEmail   string `json:"author_email,omitempty"`
	IPAddress     string `json:"ip_address,omitempty"`
	EntityPath    string `json:"entity_path,omitempty"`
	Change        string `json:"change,omitempty"`
	From          any    `json:"from,omitempty"`
	To            any    `json:"to,omitempty"`
}

func mapGitlabAuditEvent(e *gitlabAuditEvent) *access.AuditLogEntry {
	if e == nil || e.ID == 0 {
		return nil
	}
	ts := parseGitlabTime(e.CreatedAt)
	var d gitlabAuditDetails
	if len(e.Details) > 0 {
		_ = json.Unmarshal(e.Details, &d)
	}
	eventType := strings.TrimSpace(d.EventName)
	if eventType == "" {
		eventType = strings.TrimSpace(d.Change)
	}
	if eventType == "" {
		eventType = strings.TrimSpace(d.CustomMessage)
	}
	action := eventType
	rawMap := map[string]interface{}{}
	raw, _ := json.Marshal(e)
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          fmt.Sprintf("%d", e.ID),
		EventType:        eventType,
		Action:           action,
		Timestamp:        ts,
		ActorExternalID:  fmt.Sprintf("%d", e.AuthorID),
		ActorEmail:       strings.TrimSpace(d.AuthorEmail),
		TargetExternalID: fmt.Sprintf("%d", e.EntityID),
		TargetType:       strings.TrimSpace(e.EntityType),
		IPAddress:        strings.TrimSpace(d.IPAddress),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

// parseGitlabTime parses GitLab's audit-event created_at timestamps.
// The API returns RFC3339-nano timestamps (e.g. "2024-01-01T10:00:00.123Z");
// older API responses sometimes drop the fractional seconds, so we
// fall back to plain RFC3339.
func parseGitlabTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if ts, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return ts
	}
	if ts, err := time.Parse(time.RFC3339, s); err == nil {
		return ts
	}
	return time.Time{}
}

var _ access.AccessAuditor = (*GitLabAccessConnector)(nil)
