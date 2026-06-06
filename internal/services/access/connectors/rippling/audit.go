package rippling

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// FetchAccessAuditLogs streams Rippling Platform audit-log events into
// the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint (Rippling Platform API):
//
//	GET /platform/api/audit_events?start_date={iso}&limit=100&cursor={c}
//
// Rippling's audit log is plan-gated; tenants without the audit-log
// add-on receive 401/403/404 which the connector soft-skips via
// access.ErrAuditNotAvailable. Pagination uses the opaque `next_cursor`
// envelope.
func (c *RipplingAccessConnector) FetchAccessAuditLogs(
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
	pageCursor := ""
	base := c.baseURL() + "/platform/api/audit_events"
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", "100")
		if !since.IsZero() {
			q.Set("start_date", since.UTC().Format(time.RFC3339))
		}
		if pageCursor != "" {
			q.Set("cursor", pageCursor)
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("rippling: audit events: %w", err)
		}
		body, readErr := readRipplingBody(resp)
		if readErr != nil {
			return readErr
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("rippling: audit events: status %d: %s", resp.StatusCode, string(body))
		}
		var page ripplingAuditPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("rippling: decode audit events: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Events))
		batchMax := cursor
		for i := range page.Events {
			entry := mapRipplingEvent(&page.Events[i])
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
		pageCursor = strings.TrimSpace(page.NextCursor)
		if pageCursor == "" || len(page.Events) == 0 {
			return nil
		}
	}
}

type ripplingAuditPage struct {
	Events     []ripplingEvent `json:"events"`
	NextCursor string          `json:"next_cursor"`
}

type ripplingEvent struct {
	ID         string                 `json:"id"`
	Action     string                 `json:"action"`
	EventType  string                 `json:"event_type"`
	OccurredAt string                 `json:"occurred_at"`
	Actor      ripplingPrincipal      `json:"actor"`
	Target     ripplingPrincipal      `json:"target"`
	IPAddress  string                 `json:"ip_address,omitempty"`
	UserAgent  string                 `json:"user_agent,omitempty"`
	Outcome    string                 `json:"outcome,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

type ripplingPrincipal struct {
	ID    string `json:"id"`
	Email string `json:"email,omitempty"`
	Type  string `json:"type,omitempty"`
}

func mapRipplingEvent(e *ripplingEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseRipplingTime(e.OccurredAt)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	outcome := strings.TrimSpace(e.Outcome)
	if outcome == "" {
		outcome = "success"
	}
	eventType := strings.TrimSpace(e.EventType)
	if eventType == "" {
		eventType = strings.TrimSpace(e.Action)
	}
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        eventType,
		Action:           strings.TrimSpace(e.Action),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.Actor.ID),
		ActorEmail:       strings.TrimSpace(e.Actor.Email),
		TargetExternalID: strings.TrimSpace(e.Target.ID),
		TargetType:       strings.TrimSpace(e.Target.Type),
		IPAddress:        strings.TrimSpace(e.IPAddress),
		UserAgent:        strings.TrimSpace(e.UserAgent),
		Outcome:          outcome,
		RawData:          rawMap,
	}
}

func parseRipplingTime(s string) time.Time {
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

func readRipplingBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, errors.New("rippling: empty response")
	}
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

var _ access.AccessAuditor = (*RipplingAccessConnector)(nil)
