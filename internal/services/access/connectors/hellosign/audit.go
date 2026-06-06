package hellosign

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
	hellosignAuditPageSize = 100
	hellosignAuditMaxPages = 200
)

// FetchAccessAuditLogs streams HelloSign team audit-log events into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v3/team/audit_logs?page=1&per_page=100&since={iso}
//
// The audit-log API requires a HelloSign Team / Business token; personal
// tokens surface 401 / 403 / 404 which the connector soft-skips via
// access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *HelloSignAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL() + "/v3/team/audit_logs"

	for page := 1; page <= hellosignAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("per_page", fmt.Sprintf("%d", hellosignAuditPageSize))
		if !since.IsZero() {
			q.Set("since", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("hellosign: audit logs: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("hellosign: audit logs: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope hellosignAuditPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("hellosign: decode audit logs: %w", err)
		}
		// Emit one handler call per provider page so the caller can
		// persist nextSince as a monotonic cursor and resume mid-stream
		// after a partial failure (per access.AccessAuditor contract).
		batch := make([]*access.AuditLogEntry, 0, len(envelope.AuditLogs))
		batchMax := cursor
		for i := range envelope.AuditLogs {
			entry := mapHelloSignAuditEvent(&envelope.AuditLogs[i])
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
		if len(envelope.AuditLogs) < hellosignAuditPageSize {
			return nil
		}
	}
	return nil
}

type hellosignAuditEvent struct {
	ID         string `json:"id"`
	EventType  string `json:"event_type"`
	Action     string `json:"action"`
	OccurredAt string `json:"occurred_at"`
	AccountID  string `json:"account_id"`
	UserEmail  string `json:"user_email"`
	TargetID   string `json:"target_id"`
	TargetType string `json:"target_type"`
	IPAddress  string `json:"ip_address"`
}

type hellosignAuditPage struct {
	AuditLogs []hellosignAuditEvent `json:"audit_logs"`
	Page      int                   `json:"page"`
	PerPage   int                   `json:"per_page"`
}

func mapHelloSignAuditEvent(e *hellosignAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseHelloSignTime(e.OccurredAt)
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
		ActorExternalID:  strings.TrimSpace(e.AccountID),
		ActorEmail:       strings.TrimSpace(e.UserEmail),
		TargetExternalID: strings.TrimSpace(e.TargetID),
		TargetType:       strings.TrimSpace(e.TargetType),
		IPAddress:        strings.TrimSpace(e.IPAddress),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseHelloSignTime(s string) time.Time {
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

var _ access.AccessAuditor = (*HelloSignAccessConnector)(nil)
