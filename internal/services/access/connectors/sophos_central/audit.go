package sophos_central

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
	sophosCentralAuditPageSize = 100
	sophosCentralAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Sophos Central SIEM events into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /siem/v1/events?limit=100&from_date={iso}&cursor={cursor}
//
// Bearer auth via SophosCentralAccessConnector.newRequest; non-eligible
// tenants soft-skip via access.ErrAuditNotAvailable.
func (c *SophosCentralAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL() + "/siem/v1/events"

	var collected []sophosCentralAuditEvent
	cursor := ""
	for page := 0; page < sophosCentralAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", fmt.Sprintf("%d", sophosCentralAuditPageSize))
		if !since.IsZero() {
			q.Set("from_date", since.UTC().Format(time.RFC3339))
		}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("sophos_central: events: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("sophos_central: events: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope sophosCentralAuditPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("sophos_central: decode events: %w", err)
		}
		collected = append(collected, envelope.Items...)
		if envelope.HasMore && envelope.NextCursor != "" {
			cursor = envelope.NextCursor
			continue
		}
		break
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapSophosCentralAuditEvent(&collected[i])
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

type sophosCentralAuditEvent struct {
	ID         string `json:"id"`
	EventType  string `json:"type"`
	Action     string `json:"action"`
	OccurredAt string `json:"when"`
	UserID     string `json:"user_id"`
	UserEmail  string `json:"user_email"`
	EndpointID string `json:"endpoint_id"`
	IPAddress  string `json:"source_ip"`
}

type sophosCentralAuditPage struct {
	Items      []sophosCentralAuditEvent `json:"items"`
	HasMore    bool                      `json:"has_more"`
	NextCursor string                    `json:"next_cursor"`
}

func mapSophosCentralAuditEvent(e *sophosCentralAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseSophosCentralTime(e.OccurredAt)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	action := strings.TrimSpace(e.Action)
	if action == "" {
		action = strings.TrimSpace(e.EventType)
	}
	return &access.AuditLogEntry{
		EventID:          strings.TrimSpace(e.ID),
		EventType:        strings.TrimSpace(e.EventType),
		Action:           action,
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.UserID),
		ActorEmail:       strings.TrimSpace(e.UserEmail),
		TargetExternalID: strings.TrimSpace(e.EndpointID),
		IPAddress:        strings.TrimSpace(e.IPAddress),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseSophosCentralTime(s string) time.Time {
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

var _ access.AccessAuditor = (*SophosCentralAccessConnector)(nil)
