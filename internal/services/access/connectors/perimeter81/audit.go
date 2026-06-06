package perimeter81

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
	perimeter81AuditPageSize = 100
	perimeter81AuditMaxPages = 200
)

// FetchAccessAuditLogs streams Perimeter 81 audit-log events into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /api/v1/audit-logs?page=1&per_page=100&since={iso}
//
// Bearer auth via Perimeter81AccessConnector.newRequest; non-eligible
// tenants soft-skip via access.ErrAuditNotAvailable.
func (c *Perimeter81AccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL() + "/api/v1/audit-logs"

	var collected []perimeter81AuditEvent
	for page := 1; page <= perimeter81AuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("per_page", fmt.Sprintf("%d", perimeter81AuditPageSize))
		if !since.IsZero() {
			q.Set("since", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("perimeter81: audit logs: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("perimeter81: audit logs: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope perimeter81AuditPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("perimeter81: decode audit logs: %w", err)
		}
		collected = append(collected, envelope.Data...)
		if len(envelope.Data) < perimeter81AuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapPerimeter81AuditEvent(&collected[i])
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

type perimeter81AuditEvent struct {
	ID         string `json:"id"`
	EventType  string `json:"event_type"`
	Action     string `json:"action"`
	OccurredAt string `json:"occurred_at"`
	UserID     string `json:"user_id"`
	UserEmail  string `json:"user_email"`
	NetworkID  string `json:"network_id"`
	IPAddress  string `json:"ip_address"`
}

type perimeter81AuditPage struct {
	Data []perimeter81AuditEvent `json:"data"`
}

func mapPerimeter81AuditEvent(e *perimeter81AuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parsePerimeter81Time(e.OccurredAt)
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
		TargetExternalID: strings.TrimSpace(e.NetworkID),
		IPAddress:        strings.TrimSpace(e.IPAddress),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parsePerimeter81Time(s string) time.Time {
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

var _ access.AccessAuditor = (*Perimeter81AccessConnector)(nil)
