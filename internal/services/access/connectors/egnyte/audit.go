package egnyte

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// FetchAccessAuditLogs streams Egnyte audit events into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /pubapi/v2/audit/events?startDate={ts}&offset=N&count=100
//
// Pagination is offset/count-based; iteration stops when a page returns
// fewer than `count` rows. Domains without an audit-reporting licence
// receive 401/403/404 which collapses to access.ErrAuditNotAvailable
// so the worker soft-skips the tenant.
func (c *EgnyteAccessConnector) FetchAccessAuditLogs(
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
	offset := 0
	const limit = 100
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("count", fmt.Sprintf("%d", limit))
		q.Set("offset", fmt.Sprintf("%d", offset))
		if !since.IsZero() {
			q.Set("startDate", since.UTC().Format(time.RFC3339))
		}
		fullURL := c.baseURL(cfg) + "/pubapi/v2/audit/events?" + q.Encode()
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
			return fmt.Errorf("egnyte: audit/events: status %d: %s", resp.StatusCode, string(body))
		}
		var page egnyteAuditPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("egnyte: decode audit page: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Events))
		batchMax := cursor
		for i := range page.Events {
			entry := mapEgnyteAuditEvent(&page.Events[i])
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
		if len(page.Events) < limit {
			return nil
		}
		offset += limit
	}
}

type egnyteAuditPage struct {
	Events []egnyteAuditEvent `json:"events"`
	Total  int                `json:"total,omitempty"`
}

type egnyteAuditEvent struct {
	ID         string                 `json:"id"`
	EventType  string                 `json:"eventType"`
	Action     string                 `json:"action,omitempty"`
	Timestamp  string                 `json:"timestamp"`
	User       string                 `json:"user,omitempty"`
	UserEmail  string                 `json:"userEmail,omitempty"`
	UserID     string                 `json:"userId,omitempty"`
	IPAddress  string                 `json:"ipAddress,omitempty"`
	UserAgent  string                 `json:"userAgent,omitempty"`
	TargetID   string                 `json:"targetId,omitempty"`
	TargetType string                 `json:"targetType,omitempty"`
	Path       string                 `json:"path,omitempty"`
	Outcome    string                 `json:"outcome,omitempty"`
	Extra      map[string]interface{} `json:"extra,omitempty"`
}

func mapEgnyteAuditEvent(e *egnyteAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseEgnyteTime(e.Timestamp)
	rawMap := map[string]interface{}{}
	raw, _ := json.Marshal(e)
	_ = json.Unmarshal(raw, &rawMap)
	action := strings.TrimSpace(e.Action)
	if action == "" {
		action = strings.TrimSpace(e.EventType)
	}
	target := strings.TrimSpace(e.TargetID)
	if target == "" {
		target = strings.TrimSpace(e.Path)
	}
	outcome := strings.ToLower(strings.TrimSpace(e.Outcome))
	if outcome == "" {
		outcome = "success"
	}
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        strings.TrimSpace(e.EventType),
		Action:           action,
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.UserID),
		ActorEmail:       strings.TrimSpace(e.UserEmail),
		TargetExternalID: target,
		TargetType:       strings.TrimSpace(e.TargetType),
		IPAddress:        strings.TrimSpace(e.IPAddress),
		UserAgent:        strings.TrimSpace(e.UserAgent),
		Outcome:          outcome,
		RawData:          rawMap,
	}
}

// parseEgnyteTime parses Egnyte's audit-event timestamps. The API
// emits RFC3339 with optional millisecond precision.
func parseEgnyteTime(s string) time.Time {
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

var _ access.AccessAuditor = (*EgnyteAccessConnector)(nil)
