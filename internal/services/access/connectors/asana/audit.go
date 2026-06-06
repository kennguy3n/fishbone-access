package asana

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

// asanaAuditMaxPages bounds a single FetchAccessAuditLogs run, matching the
// defensive cap used by the other connectors. The checkpoint (nextSince) is
// persisted per page, so hitting the cap simply defers the remaining events to
// the next sync cycle rather than looping unboundedly on a misbehaving cursor.
const asanaAuditMaxPages = 200

// FetchAccessAuditLogs streams Asana Enterprise audit-log events into
// the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /workspaces/{workspace_gid}/audit_log_events?start_at={since}
//	    &limit=100&offset={cursor}
//
// Pagination uses Asana's `next_page.offset` opaque cursor. The audit
// log API is Enterprise-only; non-eligible workspaces receive a 402/403
// / `not_authorized` error which collapses to access.ErrAuditNotAvailable
// so the worker soft-skips the tenant.
func (c *AsanaAccessConnector) FetchAccessAuditLogs(
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
	offset := ""
	for pageNum := 0; pageNum < asanaAuditMaxPages; pageNum++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", "100")
		if !since.IsZero() {
			q.Set("start_at", since.UTC().Format(time.RFC3339))
		}
		if offset != "" {
			q.Set("offset", offset)
		}
		path := "/workspaces/" + url.PathEscape(cfg.WorkspaceGID) + "/audit_log_events?" + q.Encode()
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
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusPaymentRequired, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("asana: audit_log_events: status %d: %s", resp.StatusCode, string(body))
		}
		var page asanaAuditPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("asana: decode audit page: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Data))
		batchMax := cursor
		for i := range page.Data {
			entry := mapAsanaAuditEvent(&page.Data[i])
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
		next := strings.TrimSpace(page.NextPage.Offset)
		if next == "" {
			return nil
		}
		offset = next
	}
	return nil
}

type asanaAuditPage struct {
	Data     []asanaAuditEvent `json:"data"`
	NextPage struct {
		Offset string `json:"offset,omitempty"`
		Path   string `json:"path,omitempty"`
	} `json:"next_page"`
}

type asanaAuditEvent struct {
	GID       string `json:"gid"`
	EventType string `json:"event_type"`
	CreatedAt string `json:"created_at"`
	Actor     struct {
		GID   string `json:"gid"`
		Type  string `json:"actor_type,omitempty"`
		Name  string `json:"name,omitempty"`
		Email string `json:"email,omitempty"`
	} `json:"actor"`
	Resource struct {
		GID  string `json:"gid"`
		Type string `json:"resource_type,omitempty"`
		Name string `json:"name,omitempty"`
	} `json:"resource"`
	Context map[string]interface{} `json:"context,omitempty"`
}

func mapAsanaAuditEvent(e *asanaAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.GID) == "" {
		return nil
	}
	ts := parseAsanaTime(e.CreatedAt)
	if ts.IsZero() {
		return nil
	}
	rawMap := map[string]interface{}{}
	raw, _ := json.Marshal(e)
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          e.GID,
		EventType:        strings.TrimSpace(e.EventType),
		Action:           strings.TrimSpace(e.EventType),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.Actor.GID),
		ActorEmail:       strings.TrimSpace(e.Actor.Email),
		TargetExternalID: strings.TrimSpace(e.Resource.GID),
		TargetType:       strings.TrimSpace(e.Resource.Type),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

// parseAsanaTime tries RFC3339Nano first, then RFC3339; Asana's
// created_at typically includes microsecond precision but older
// recordings omit fractional seconds.
func parseAsanaTime(s string) time.Time {
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

var _ access.AccessAuditor = (*AsanaAccessConnector)(nil)
