package wrike

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
	wrikeAuditPageSize = 100
	wrikeAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Wrike audit_log entries into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /api/v4/audit_log?pageSize=100&nextPageToken=...
//
// The audit-log API requires Enterprise plan; non-Enterprise tokens
// receive 401 / 403 / 404 which the connector soft-skips via
// access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *WrikeAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL(cfg) + "/api/v4/audit_log"

	var collected []wrikeAuditEvent
	cursor := ""
	for pages := 0; pages < wrikeAuditMaxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("pageSize", fmt.Sprintf("%d", wrikeAuditPageSize))
		if cursor != "" {
			q.Set("nextPageToken", cursor)
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("wrike: audit log: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("wrike: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope wrikeAuditResponse
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("wrike: decode audit log: %w", err)
		}
		olderThanCursor := false
		for i := range envelope.Data {
			ts := parseWrikeAuditTime(envelope.Data[i].EventDate)
			if !since.IsZero() && !ts.IsZero() && !ts.After(since) {
				olderThanCursor = true
				continue
			}
			collected = append(collected, envelope.Data[i])
		}
		if olderThanCursor || envelope.NextPageToken == "" {
			break
		}
		cursor = envelope.NextPageToken
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapWrikeAuditEvent(&collected[i])
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

type wrikeAuditEvent struct {
	ID         string `json:"id"`
	Operation  string `json:"operation"`
	EventDate  string `json:"eventDate"`
	UserID     string `json:"userId"`
	UserEmail  string `json:"userEmail"`
	ObjectType string `json:"objectType"`
	ObjectID   string `json:"objectId"`
	IPAddress  string `json:"ipAddress"`
}

type wrikeAuditResponse struct {
	Kind          string            `json:"kind"`
	Data          []wrikeAuditEvent `json:"data"`
	NextPageToken string            `json:"nextPageToken"`
}

func mapWrikeAuditEvent(e *wrikeAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseWrikeAuditTime(e.EventDate)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        strings.TrimSpace(e.Operation),
		Action:           strings.TrimSpace(e.Operation),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.UserID),
		ActorEmail:       strings.TrimSpace(e.UserEmail),
		TargetExternalID: strings.TrimSpace(e.ObjectID),
		TargetType:       strings.TrimSpace(e.ObjectType),
		IPAddress:        strings.TrimSpace(e.IPAddress),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseWrikeAuditTime(s string) time.Time {
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
