package figma

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

// FetchAccessAuditLogs streams Figma activity-log events into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v1/activity_logs?start_time={unix}&cursor={cursor}&order=asc
//
// The activity log API is only available on Figma Organization /
// Enterprise plans; non-eligible tenants receive 401/403/404 which
// collapses to access.ErrAuditNotAvailable so the worker soft-skips
// the tenant instead of looping forever.
func (c *FigmaAccessConnector) FetchAccessAuditLogs(
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
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("order", "asc")
		if !since.IsZero() {
			q.Set("start_time", strconv.FormatInt(since.UTC().Unix(), 10))
		}
		if pageCursor != "" {
			q.Set("cursor", pageCursor)
		}
		path := "/activity_logs?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
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
			return fmt.Errorf("figma: activity_logs: status %d: %s", resp.StatusCode, string(body))
		}
		var page figmaActivityPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("figma: decode activity page: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Meta.Events))
		batchMax := cursor
		for i := range page.Meta.Events {
			entry := mapFigmaActivity(&page.Meta.Events[i])
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
		next := strings.TrimSpace(page.Pagination.NextPage)
		if next == "" {
			return nil
		}
		pageCursor = next
	}
}

type figmaActivityPage struct {
	Meta struct {
		Events []figmaActivityEvent `json:"events"`
	} `json:"meta"`
	Pagination struct {
		NextPage string `json:"next_page,omitempty"`
		Cursor   string `json:"cursor,omitempty"`
	} `json:"pagination"`
}

type figmaActivityEvent struct {
	ID        string `json:"id"`
	EventType string `json:"event_type"`
	Timestamp string `json:"timestamp"`
	Actor     struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name,omitempty"`
		Type  string `json:"type,omitempty"`
	} `json:"actor"`
	Context struct {
		IPAddress string `json:"ip_address,omitempty"`
		UserAgent string `json:"user_agent,omitempty"`
	} `json:"context"`
	Entity struct {
		ID   string `json:"id"`
		Type string `json:"type,omitempty"`
		Name string `json:"name,omitempty"`
	} `json:"entity"`
	Details map[string]interface{} `json:"details,omitempty"`
}

func mapFigmaActivity(e *figmaActivityEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseFigmaTime(e.Timestamp)
	rawMap := map[string]interface{}{}
	raw, _ := json.Marshal(e)
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        strings.TrimSpace(e.EventType),
		Action:           strings.TrimSpace(e.EventType),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.Actor.ID),
		ActorEmail:       strings.TrimSpace(e.Actor.Email),
		TargetExternalID: strings.TrimSpace(e.Entity.ID),
		TargetType:       strings.TrimSpace(e.Entity.Type),
		IPAddress:        strings.TrimSpace(e.Context.IPAddress),
		UserAgent:        strings.TrimSpace(e.Context.UserAgent),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

// parseFigmaTime parses Figma's activity-log timestamps. The API has
// emitted both RFC3339 strings and Unix epoch seconds depending on
// version, so we accept both shapes.
func parseFigmaTime(s string) time.Time {
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

var _ access.AccessAuditor = (*FigmaAccessConnector)(nil)
