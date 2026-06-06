package clickup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// FetchAccessAuditLogs streams ClickUp Enterprise audit-log events
// into the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint (Enterprise plan only):
//
//	GET /api/v2/team/{team_id}/audit?date_from={ms}&page=N&page_size=100
//
// Pagination is page-numbered; iteration stops when a page returns
// fewer than `pageSize` rows. Tenants without the Enterprise audit
// add-on receive 401/403/404 which collapses to
// access.ErrAuditNotAvailable so the worker soft-skips the tenant.
func (c *ClickUpAccessConnector) FetchAccessAuditLogs(
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
	page := 0
	const pageSize = 100
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page", strconv.Itoa(page))
		q.Set("page_size", strconv.Itoa(pageSize))
		if !since.IsZero() {
			q.Set("date_from", strconv.FormatInt(since.UTC().UnixMilli(), 10))
		}
		fullURL := fmt.Sprintf("%s/api/v2/team/%s/audit?%s", c.baseURL(), url.PathEscape(cfg.TeamID), q.Encode())
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return err
		}
		resp, err := c.doRaw(req)
		if err != nil {
			return err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("clickup: audit: status %d: %s", resp.StatusCode, string(body))
		}
		var pg clickupAuditPage
		if err := json.Unmarshal(body, &pg); err != nil {
			return fmt.Errorf("clickup: decode audit page: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(pg.Events))
		batchMax := cursor
		for i := range pg.Events {
			entry := mapClickupEvent(&pg.Events[i])
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
		if len(pg.Events) < pageSize {
			return nil
		}
		page++
	}
}

type clickupAuditPage struct {
	Events []clickupAuditEvent `json:"events"`
}

type clickupAuditEvent struct {
	ID          string `json:"id"`
	EventType   string `json:"event_type"`
	Date        string `json:"date"`
	WorkspaceID string `json:"workspace_id,omitempty"`
	User        struct {
		ID       json.Number `json:"id"`
		Username string      `json:"username,omitempty"`
		Email    string      `json:"email,omitempty"`
	} `json:"user"`
	Source struct {
		IP        string `json:"ip,omitempty"`
		UserAgent string `json:"user_agent,omitempty"`
	} `json:"source"`
	Target struct {
		ID   string `json:"id,omitempty"`
		Type string `json:"type,omitempty"`
	} `json:"target"`
	Meta map[string]interface{} `json:"meta,omitempty"`
}

func mapClickupEvent(e *clickupAuditEvent) *access.AuditLogEntry {
	if e == nil {
		return nil
	}
	id := strings.TrimSpace(e.ID)
	if id == "" {
		id = strings.TrimSpace(e.Date) + ":" + strings.TrimSpace(e.EventType)
		if strings.TrimSpace(id) == ":" {
			return nil
		}
	}
	ts := parseClickupTime(e.Date)
	rawMap := map[string]interface{}{}
	raw, _ := json.Marshal(e)
	_ = json.Unmarshal(raw, &rawMap)
	actor := strings.TrimSpace(e.User.ID.String())
	if actor == "0" {
		actor = ""
	}
	return &access.AuditLogEntry{
		EventID:          id,
		EventType:        strings.TrimSpace(e.EventType),
		Action:           strings.TrimSpace(e.EventType),
		Timestamp:        ts,
		ActorExternalID:  actor,
		ActorEmail:       strings.TrimSpace(e.User.Email),
		TargetExternalID: strings.TrimSpace(e.Target.ID),
		TargetType:       strings.TrimSpace(e.Target.Type),
		IPAddress:        strings.TrimSpace(e.Source.IP),
		UserAgent:        strings.TrimSpace(e.Source.UserAgent),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

// parseClickupTime accepts both RFC3339 strings and Unix epoch
// milliseconds (the audit API has used both formats across releases).
func parseClickupTime(s string) time.Time {
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
	if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 0 {
		if n > 1_000_000_000_000 {
			return time.UnixMilli(n).UTC()
		}
		return time.Unix(n, 0).UTC()
	}
	return time.Time{}
}

var _ access.AccessAuditor = (*ClickUpAccessConnector)(nil)
