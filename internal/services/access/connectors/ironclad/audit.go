package ironclad

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
	ironcladAuditPageSize = 100
	ironcladAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Ironclad audit-log events into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /public/api/v1/audit-logs?page=1&per_page=100&since={iso}
//
// The audit-log API is gated behind Ironclad's Enterprise tier; tokens
// without the entitlement surface 401 / 403 / 404, which the connector
// soft-skips via access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *IroncladAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL() + "/public/api/v1/audit-logs"

	cursor := since
	for page := 1; page <= ironcladAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("per_page", fmt.Sprintf("%d", ironcladAuditPageSize))
		if !since.IsZero() {
			q.Set("since", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("ironclad: audit logs: %w", err)
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if readErr != nil {
			// Surface read failures instead of advancing the cursor on a
			// truncated body that could parse as a short page and end the
			// sweep early (matches jfrog/jira read-error handling).
			return fmt.Errorf("ironclad: read audit logs body: %w", readErr)
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("ironclad: audit logs: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope ironcladAuditPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("ironclad: decode audit logs: %w", err)
		}
		// Emit each page as it is fetched so the caller persists nextSince
		// per page as a monotonic cursor (AccessAuditor contract). batchMax
		// starts at the running cursor so it never moves backward, and a
		// mid-stream handler failure only replays the un-acked tail.
		batch := make([]*access.AuditLogEntry, 0, len(envelope.AuditLogs))
		batchMax := cursor
		for i := range envelope.AuditLogs {
			entry := mapIroncladAuditEvent(&envelope.AuditLogs[i])
			if entry == nil {
				continue
			}
			if entry.Timestamp.After(batchMax) {
				batchMax = entry.Timestamp
			}
			batch = append(batch, entry)
		}
		if len(batch) > 0 {
			if err := handler(batch, batchMax, access.DefaultAuditPartition); err != nil {
				return err
			}
			cursor = batchMax
		}
		if len(envelope.AuditLogs) < ironcladAuditPageSize {
			break
		}
	}
	return nil
}

type ironcladAuditEvent struct {
	ID          string `json:"id"`
	EventType   string `json:"event_type"`
	Action      string `json:"action"`
	Timestamp   string `json:"timestamp"`
	UserID      string `json:"user_id"`
	UserEmail   string `json:"user_email"`
	WorkflowID  string `json:"workflow_id"`
	IPAddress   string `json:"ip_address"`
	UserAgent   string `json:"user_agent"`
	Description string `json:"description"`
}

type ironcladAuditPage struct {
	AuditLogs []ironcladAuditEvent `json:"audit_logs"`
	Page      int                  `json:"page"`
	PerPage   int                  `json:"per_page"`
}

func mapIroncladAuditEvent(e *ironcladAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseIroncladTime(e.Timestamp)
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
		TargetExternalID: strings.TrimSpace(e.WorkflowID),
		IPAddress:        strings.TrimSpace(e.IPAddress),
		UserAgent:        strings.TrimSpace(e.UserAgent),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseIroncladTime(s string) time.Time {
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

var _ access.AccessAuditor = (*IroncladAccessConnector)(nil)
