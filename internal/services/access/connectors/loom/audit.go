package loom

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
	loomAuditPageSize = 100
	loomAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Loom workspace audit events into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v1/audit_logs?limit=100&cursor=...
//
// Loom returns events newest-first with an opaque next-cursor. Tenants
// without a Business / Enterprise plan receive 401 / 403 / 404, which
// the connector soft-skips via access.ErrAuditNotAvailable.
func (c *LoomAccessConnector) FetchAccessAuditLogs(
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

	var collected []loomAuditEvent
	cursor := ""
	for pages := 0; pages < loomAuditMaxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", fmt.Sprintf("%d", loomAuditPageSize))
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, c.baseURL()+"/v1/audit_logs?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("loom: audit log: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("loom: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope loomAuditResponse
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("loom: decode audit log: %w", err)
		}
		olderThanCursor := false
		for i := range envelope.Data {
			ts := parseLoomAuditTime(envelope.Data[i].Timestamp)
			if !since.IsZero() && !ts.IsZero() && !ts.After(since) {
				olderThanCursor = true
				continue
			}
			collected = append(collected, envelope.Data[i])
		}
		if olderThanCursor || envelope.NextCursor == "" {
			break
		}
		cursor = envelope.NextCursor
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapLoomAuditEvent(&collected[i])
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

type loomAuditEvent struct {
	ID         string `json:"id"`
	Event      string `json:"event"`
	Action     string `json:"action"`
	Timestamp  string `json:"timestamp"`
	ActorID    string `json:"actor_id"`
	ActorEmail string `json:"actor_email"`
	TargetID   string `json:"target_id"`
	TargetType string `json:"target_type"`
	IPAddress  string `json:"ip_address"`
}

type loomAuditResponse struct {
	Data       []loomAuditEvent `json:"data"`
	NextCursor string           `json:"next_cursor"`
}

func mapLoomAuditEvent(e *loomAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseLoomAuditTime(e.Timestamp)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        strings.TrimSpace(e.Event),
		Action:           strings.TrimSpace(e.Action),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.ActorID),
		ActorEmail:       strings.TrimSpace(e.ActorEmail),
		TargetExternalID: strings.TrimSpace(e.TargetID),
		TargetType:       strings.TrimSpace(e.TargetType),
		IPAddress:        strings.TrimSpace(e.IPAddress),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseLoomAuditTime(s string) time.Time {
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
