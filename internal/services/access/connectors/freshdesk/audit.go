package freshdesk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// FetchAccessAuditLogs streams Freshdesk audit-log events into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint (Pro / Enterprise plans only):
//
//	GET /api/v2/audit_log?since={ts}&page=N&per_page=100
//
// Pagination is page-numbered; iteration stops when a page returns
// fewer than `per_page` rows. Plans without the audit-log feature
// receive 401/403/404 which collapses to access.ErrAuditNotAvailable
// so the worker soft-skips the tenant rather than looping.
func (c *FreshdeskAccessConnector) FetchAccessAuditLogs(
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
	cursor := since
	page := 1
	const perPage = 100
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("per_page", strconv.Itoa(perPage))
		q.Set("page", strconv.Itoa(page))
		if !since.IsZero() {
			q.Set("since", since.UTC().Format(time.RFC3339))
		}
		fullURL := c.baseURL(cfg) + "/api/v2/audit_log?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return err
		}
		resp, err := c.doRaw(req)
		if err != nil {
			return err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("freshdesk: audit_log: status %d: %s", resp.StatusCode, string(body))
		}
		entries, err := decodeFreshdeskAuditPage(body)
		if err != nil {
			return err
		}
		batch := make([]*access.AuditLogEntry, 0, len(entries))
		batchMax := cursor
		for i := range entries {
			entry := mapFreshdeskAuditEvent(&entries[i])
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
		if len(entries) < perPage {
			return nil
		}
		page++
	}
}

// decodeFreshdeskAuditPage tolerates both the legacy `[{...}]` shape and
// the newer `{"audit_logs": [...]}` envelope returned by some plans.
func decodeFreshdeskAuditPage(body []byte) ([]freshdeskAuditEvent, error) {
	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, "[") {
		var entries []freshdeskAuditEvent
		if err := json.Unmarshal(body, &entries); err != nil {
			return nil, fmt.Errorf("freshdesk: decode audit_log: %w", err)
		}
		return entries, nil
	}
	var envelope struct {
		AuditLogs []freshdeskAuditEvent `json:"audit_logs"`
		Logs      []freshdeskAuditEvent `json:"logs"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("freshdesk: decode audit_log envelope: %w", err)
	}
	if len(envelope.AuditLogs) > 0 {
		return envelope.AuditLogs, nil
	}
	return envelope.Logs, nil
}

type freshdeskAuditEvent struct {
	ID         json.Number            `json:"id"`
	UserID     json.Number            `json:"user_id"`
	UserName   string                 `json:"user_name,omitempty"`
	UserEmail  string                 `json:"user_email,omitempty"`
	Action     string                 `json:"action"`
	Source     string                 `json:"source,omitempty"`
	Object     string                 `json:"object,omitempty"`
	ObjectID   json.Number            `json:"object_id,omitempty"`
	ObjectName string                 `json:"object_name,omitempty"`
	IPAddress  string                 `json:"ip_address,omitempty"`
	UserAgent  string                 `json:"user_agent,omitempty"`
	CreatedAt  string                 `json:"created_at"`
	Outcome    string                 `json:"outcome,omitempty"`
	Changes    map[string]interface{} `json:"changes,omitempty"`
}

func mapFreshdeskAuditEvent(e *freshdeskAuditEvent) *access.AuditLogEntry {
	if e == nil {
		return nil
	}
	id := strings.TrimSpace(e.ID.String())
	if id == "" || id == "0" {
		return nil
	}
	ts := parseFreshdeskTime(e.CreatedAt)
	if ts.IsZero() {
		return nil
	}
	rawMap := map[string]interface{}{}
	raw, _ := json.Marshal(e)
	_ = json.Unmarshal(raw, &rawMap)
	actor := strings.TrimSpace(e.UserID.String())
	if actor == "0" {
		actor = ""
	}
	target := strings.TrimSpace(e.ObjectID.String())
	if target == "0" {
		target = ""
	}
	outcome := strings.ToLower(strings.TrimSpace(e.Outcome))
	if outcome == "" {
		outcome = "success"
	}
	return &access.AuditLogEntry{
		EventID:          id,
		EventType:        strings.TrimSpace(e.Action),
		Action:           strings.TrimSpace(e.Action),
		Timestamp:        ts,
		ActorExternalID:  actor,
		ActorEmail:       strings.TrimSpace(e.UserEmail),
		TargetExternalID: target,
		TargetType:       strings.TrimSpace(e.Object),
		IPAddress:        strings.TrimSpace(e.IPAddress),
		UserAgent:        strings.TrimSpace(e.UserAgent),
		Outcome:          outcome,
		RawData:          rawMap,
	}
}

// parseFreshdeskTime parses Freshdesk's created_at timestamps. The API
// emits RFC3339Z; older payloads omit fractional seconds.
func parseFreshdeskTime(s string) time.Time {
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

var _ access.AccessAuditor = (*FreshdeskAccessConnector)(nil)
