package segment

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
	segmentAuditPageSize = 100
	segmentAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Segment workspace audit-trail events into
// the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /audit-trail/events?pagination.count=100&pagination.cursor={cursor}
//
// The audit-trail API requires a Workspace Owner Public API token; lesser
// tokens surface 401 / 403 / 404 which the connector soft-skips via
// access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *SegmentAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL() + "/audit-trail/events"

	var collected []segmentAuditEvent
	cursor := ""
	for page := 0; page < segmentAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("pagination.count", fmt.Sprintf("%d", segmentAuditPageSize))
		if cursor != "" {
			q.Set("pagination.cursor", cursor)
		}
		if !since.IsZero() {
			q.Set("startTime", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("segment: audit-trail events: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("segment: audit-trail events: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope segmentAuditPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("segment: decode audit-trail events: %w", err)
		}
		collected = append(collected, envelope.AuditTrailEvents...)
		next := strings.TrimSpace(envelope.Pagination.Next)
		if next == "" || len(envelope.AuditTrailEvents) == 0 {
			break
		}
		cursor = next
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapSegmentAuditEvent(&collected[i])
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

type segmentAuditEvent struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Action    string `json:"action"`
	Timestamp string `json:"timestamp"`
	UserID    string `json:"userId"`
	UserEmail string `json:"userEmail"`
	Resource  string `json:"resource"`
	IPAddress string `json:"ipAddress"`
}

type segmentAuditPage struct {
	AuditTrailEvents []segmentAuditEvent `json:"audit_trail_events"`
	Pagination       struct {
		Next string `json:"next"`
	} `json:"pagination"`
}

func mapSegmentAuditEvent(e *segmentAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseSegmentTime(e.Timestamp)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	action := strings.TrimSpace(e.Action)
	if action == "" {
		action = strings.TrimSpace(e.Type)
	}
	return &access.AuditLogEntry{
		EventID:          strings.TrimSpace(e.ID),
		EventType:        strings.TrimSpace(e.Type),
		Action:           action,
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.UserID),
		ActorEmail:       strings.TrimSpace(e.UserEmail),
		TargetExternalID: strings.TrimSpace(e.Resource),
		IPAddress:        strings.TrimSpace(e.IPAddress),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseSegmentTime(s string) time.Time {
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

var _ access.AccessAuditor = (*SegmentAccessConnector)(nil)
