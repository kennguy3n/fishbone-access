package miro

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

// FetchAccessAuditLogs streams Miro Enterprise audit-log events into
// the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint (Enterprise plan only):
//
//	GET /v2/audit/logs?from={since}&limit=100&cursor={cursor}
//
// Pagination uses Miro's `cursor` opaque token. Tenants without an
// Enterprise audit licence receive 401/403/404 which collapses to
// access.ErrAuditNotAvailable so the worker soft-skips the tenant
// rather than looping forever.
func (c *MiroAccessConnector) FetchAccessAuditLogs(
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
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", "100")
		if !since.IsZero() {
			q.Set("from", since.UTC().Format(time.RFC3339))
		}
		if pageCursor != "" {
			q.Set("cursor", pageCursor)
		}
		path := "/audit/logs?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
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
			return fmt.Errorf("miro: audit logs: status %d: %s", resp.StatusCode, string(body))
		}
		var page miroAuditPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("miro: decode audit page: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Data))
		batchMax := cursor
		for i := range page.Data {
			entry := mapMiroAuditEvent(&page.Data[i])
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
		next := strings.TrimSpace(page.Cursor)
		if next == "" {
			return nil
		}
		pageCursor = next
	}
}

type miroAuditPage struct {
	Data   []miroAuditEvent `json:"data"`
	Cursor string           `json:"cursor,omitempty"`
	Size   int              `json:"size,omitempty"`
	Total  int              `json:"total,omitempty"`
}

type miroAuditEvent struct {
	ID        string `json:"id"`
	Event     string `json:"event"`
	CreatedAt string `json:"createdAt"`
	CreatedBy struct {
		ID    string `json:"id"`
		Type  string `json:"type,omitempty"`
		Email string `json:"email,omitempty"`
		Name  string `json:"name,omitempty"`
	} `json:"createdBy"`
	Object struct {
		ID   string `json:"id"`
		Type string `json:"type"`
		Name string `json:"name,omitempty"`
	} `json:"object"`
	Context struct {
		IP        string `json:"ip,omitempty"`
		UserAgent string `json:"userAgent,omitempty"`
		OrgID     string `json:"orgId,omitempty"`
	} `json:"context"`
	Details map[string]interface{} `json:"details,omitempty"`
}

func mapMiroAuditEvent(e *miroAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseMiroTime(e.CreatedAt)
	if ts.IsZero() {
		return nil
	}
	rawMap := map[string]interface{}{}
	raw, _ := json.Marshal(e)
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        strings.TrimSpace(e.Event),
		Action:           strings.TrimSpace(e.Event),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.CreatedBy.ID),
		ActorEmail:       strings.TrimSpace(e.CreatedBy.Email),
		TargetExternalID: strings.TrimSpace(e.Object.ID),
		TargetType:       strings.TrimSpace(e.Object.Type),
		IPAddress:        strings.TrimSpace(e.Context.IP),
		UserAgent:        strings.TrimSpace(e.Context.UserAgent),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

// parseMiroTime parses Miro's createdAt timestamps. The API emits
// RFC3339 strings, optionally with millisecond precision.
func parseMiroTime(s string) time.Time {
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

var _ access.AccessAuditor = (*MiroAccessConnector)(nil)
