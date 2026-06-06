package anvyl

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
	anvylAuditPageSize = 100
	anvylAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Anvyl supply-chain audit events into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /api/v1/audit-logs?page=1&per_page=100&since={iso}
//
// The audit-log API requires the workspace-admin scope; tokens without
// it surface 401 / 403 / 404 which the connector soft-skips via
// access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *AnvylAccessConnector) FetchAccessAuditLogs(
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

	var collected []anvylAuditEvent
	for page := 1; page <= anvylAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("per_page", fmt.Sprintf("%d", anvylAuditPageSize))
		if !since.IsZero() {
			q.Set("since", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("anvyl: audit logs: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("anvyl: audit logs: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope anvylAuditPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("anvyl: decode audit logs: %w", err)
		}
		collected = append(collected, envelope.Data...)
		if len(envelope.Data) < anvylAuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapAnvylAuditEvent(&collected[i])
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

type anvylAuditEvent struct {
	ID         string `json:"id"`
	EventType  string `json:"event_type"`
	Action     string `json:"action"`
	OccurredAt string `json:"occurred_at"`
	UserID     string `json:"user_id"`
	UserEmail  string `json:"user_email"`
	OrderID    string `json:"order_id"`
	IPAddress  string `json:"ip_address"`
}

type anvylAuditPage struct {
	Data    []anvylAuditEvent `json:"data"`
	Page    int               `json:"page"`
	PerPage int               `json:"per_page"`
}

func mapAnvylAuditEvent(e *anvylAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseAnvylTime(e.OccurredAt)
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
		TargetExternalID: strings.TrimSpace(e.OrderID),
		IPAddress:        strings.TrimSpace(e.IPAddress),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseAnvylTime(s string) time.Time {
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

var _ access.AccessAuditor = (*AnvylAccessConnector)(nil)
