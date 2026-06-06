package notion

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// FetchAccessAuditLogs streams Notion audit log entries into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint (Enterprise plan only):
//
//	GET /v1/audit_log?start_date={since}&page_size=100&start_cursor=...
//
// Pagination uses Notion's `next_cursor` / `has_more` envelope. The
// audit log API is only available on Enterprise workspaces; non-eligible
// workspaces receive a 401/403/404 / `unsupported_audit_log` API error
// which we collapse to access.ErrAuditNotAvailable so the worker
// soft-skips the tenant.
func (c *NotionAccessConnector) FetchAccessAuditLogs(
	ctx context.Context,
	_ map[string]interface{},
	secretsRaw map[string]interface{},
	sincePartitions map[string]time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	secrets, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return err
	}
	if err := secrets.validate(); err != nil {
		return err
	}
	since := sincePartitions[access.DefaultAuditPartition]
	cursor := since
	pageCursor := ""
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page_size", "100")
		if !since.IsZero() {
			q.Set("start_date", since.UTC().Format(time.RFC3339))
		}
		if pageCursor != "" {
			q.Set("start_cursor", pageCursor)
		}
		path := "/v1/audit_log?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("notion: audit log: %w", err)
		}
		body, readErr := readNotionResponse(resp)
		if readErr != nil {
			return readErr
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			// Notion returns 400 with `code:"unsupported_audit_log"` for
			// workspaces that haven't enabled audit logging; treat as
			// not-available rather than a hard failure.
			var perr notionAPIError
			if json.Unmarshal(body, &perr) == nil {
				if strings.EqualFold(perr.Code, "unsupported_audit_log") ||
					strings.EqualFold(perr.Code, "restricted_resource") ||
					strings.EqualFold(perr.Code, "unauthorized") {
					return access.ErrAuditNotAvailable
				}
			}
			return fmt.Errorf("notion: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var page notionAuditPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("notion: decode audit page: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Results))
		batchMax := cursor
		for i := range page.Results {
			entry := mapNotionAuditEvent(&page.Results[i])
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
		if !page.HasMore || strings.TrimSpace(page.NextCursor) == "" {
			return nil
		}
		pageCursor = page.NextCursor
	}
}

type notionAuditPage struct {
	Object     string             `json:"object"`
	Results    []notionAuditEvent `json:"results"`
	HasMore    bool               `json:"has_more"`
	NextCursor string             `json:"next_cursor"`
}

type notionAuditEvent struct {
	ID        string `json:"id"`
	EventType string `json:"event_type"`
	Timestamp string `json:"timestamp"`
	Actor     struct {
		ID    string `json:"id"`
		Type  string `json:"type,omitempty"`
		Email string `json:"email,omitempty"`
	} `json:"actor"`
	WorkspaceID string `json:"workspace_id,omitempty"`
	Target      struct {
		ID   string `json:"id"`
		Type string `json:"type,omitempty"`
	} `json:"target"`
	IPAddress string                 `json:"ip_address,omitempty"`
	UserAgent string                 `json:"user_agent,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

type notionAPIError struct {
	Object  string `json:"object"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Status  int    `json:"status"`
}

func mapNotionAuditEvent(e *notionAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseNotionTime(e.Timestamp)
	if ts.IsZero() {
		return nil
	}
	rawMap := map[string]interface{}{}
	raw, _ := json.Marshal(e)
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        strings.TrimSpace(e.EventType),
		Action:           strings.TrimSpace(e.EventType),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.Actor.ID),
		ActorEmail:       strings.TrimSpace(e.Actor.Email),
		TargetExternalID: strings.TrimSpace(e.Target.ID),
		TargetType:       strings.TrimSpace(e.Target.Type),
		IPAddress:        strings.TrimSpace(e.IPAddress),
		UserAgent:        strings.TrimSpace(e.UserAgent),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

// parseNotionTime parses Notion's ISO-8601 timestamps, trying
// RFC3339Nano first (with fractional seconds) and falling back to
// plain RFC3339.
func parseNotionTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if ts, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return ts
	}
	if ts, err := time.Parse(time.RFC3339, s); err == nil {
		return ts
	}
	return time.Time{}
}

func readNotionResponse(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	const max = 1 << 20
	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if len(buf) >= max {
				break
			}
		}
		if err != nil {
			break
		}
	}
	return buf, nil
}

var _ access.AccessAuditor = (*NotionAccessConnector)(nil)
