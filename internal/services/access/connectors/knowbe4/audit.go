package knowbe4

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

const (
	knowbe4AuditPageSize = 100
	knowbe4AuditMaxPages = 200
)

// FetchAccessAuditLogs streams KnowBe4 admin audit-log events into
// the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v1/audit_log?page=N&per_page=100
//
// The audit-log API is admin-only; non-admin tokens receive 401 / 403
// / 404 which the connector soft-skips via
// access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *KnowBe4AccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL(cfg) + "/v1/audit_log"

	var collected []knowbe4AuditEvent
	for page := 1; page <= knowbe4AuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("per_page", fmt.Sprintf("%d", knowbe4AuditPageSize))
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("knowbe4: audit log: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("knowbe4: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var events []knowbe4AuditEvent
		if err := json.Unmarshal(body, &events); err != nil {
			return fmt.Errorf("knowbe4: decode audit log: %w", err)
		}
		olderThanCursor := false
		for i := range events {
			ts := parseKnowBe4AuditTime(events[i].EventTime)
			if !since.IsZero() && !ts.IsZero() && !ts.After(since) {
				olderThanCursor = true
				continue
			}
			collected = append(collected, events[i])
		}
		if olderThanCursor || len(events) < knowbe4AuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapKnowBe4AuditEvent(&collected[i])
		if entry == nil {
			continue
		}
		if entry.Timestamp.After(batchMax) {
			batchMax = entry.Timestamp
		}
		batch = append(batch, entry)
	}
	if len(batch) == 0 {
		return nil
	}
	return handler(batch, batchMax, access.DefaultAuditPartition)
}

type knowbe4AuditEvent struct {
	ID         int64  `json:"id"`
	EventType  string `json:"event_type"`
	EventTime  string `json:"event_time"`
	UserID     int64  `json:"user_id"`
	UserEmail  string `json:"user_email"`
	TargetID   int64  `json:"target_id"`
	TargetType string `json:"target_type"`
	Source     string `json:"source"`
}

func mapKnowBe4AuditEvent(e *knowbe4AuditEvent) *access.AuditLogEntry {
	if e == nil || e.ID == 0 {
		return nil
	}
	ts := parseKnowBe4AuditTime(e.EventTime)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          fmt.Sprintf("%d", e.ID),
		EventType:        strings.TrimSpace(e.EventType),
		Action:           strings.TrimSpace(e.EventType),
		Timestamp:        ts,
		ActorExternalID:  fmt.Sprintf("%d", e.UserID),
		ActorEmail:       strings.TrimSpace(e.UserEmail),
		TargetExternalID: fmt.Sprintf("%d", e.TargetID),
		TargetType:       strings.TrimSpace(e.TargetType),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseKnowBe4AuditTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if ts, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return ts.UTC()
	}
	if ts, err := time.Parse(time.RFC3339, s); err == nil {
		return ts.UTC()
	}
	return time.Time{}
}
