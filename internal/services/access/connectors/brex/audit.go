package brex

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
	brexAuditPageSize = 100
	brexAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Brex audit-log events into the access audit
// pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v2/audit_logs?per_page=100&page=N&created_at_gt={iso}
//
// Audit-log access requires the `audit_logs:read` scope; lower scopes
// return 401 / 403 / 404 which the connector soft-skips via
// access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *BrexAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL() + "/v2/audit_logs"

	var collected []brexAuditEvent
	for page := 1; page <= brexAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("per_page", fmt.Sprintf("%d", brexAuditPageSize))
		if !since.IsZero() {
			q.Set("created_at_gt", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("brex: audit_logs: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("brex: audit_logs: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope brexAuditPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("brex: decode audit_logs: %w", err)
		}
		collected = append(collected, envelope.Items...)
		if envelope.Page >= envelope.TotalPages || len(envelope.Items) < brexAuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapBrexAuditEvent(&collected[i])
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

type brexAuditEvent struct {
	ID         string `json:"id"`
	EventType  string `json:"event_type"`
	Action     string `json:"action"`
	CreatedAt  string `json:"created_at"`
	UserID     string `json:"user_id"`
	UserEmail  string `json:"user_email"`
	ResourceID string `json:"resource_id"`
	Outcome    string `json:"outcome"`
}

type brexAuditPage struct {
	Items      []brexAuditEvent `json:"items"`
	Page       int              `json:"page"`
	TotalPages int              `json:"total_pages"`
}

func mapBrexAuditEvent(e *brexAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseBrexTime(e.CreatedAt)
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
	outcome := strings.TrimSpace(e.Outcome)
	if outcome == "" {
		outcome = "success"
	}
	return &access.AuditLogEntry{
		EventID:          strings.TrimSpace(e.ID),
		EventType:        strings.TrimSpace(e.EventType),
		Action:           action,
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.UserID),
		ActorEmail:       strings.TrimSpace(e.UserEmail),
		TargetExternalID: strings.TrimSpace(e.ResourceID),
		Outcome:          outcome,
		RawData:          rawMap,
	}
}

func parseBrexTime(s string) time.Time {
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

var _ access.AccessAuditor = (*BrexAccessConnector)(nil)
