package airtable

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

// FetchAccessAuditLogs streams Airtable Enterprise audit-log events
// into the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint (Enterprise plan only):
//
//	GET /meta/enterpriseAccount/{id}/auditLogEvents?startTime={since}
//	    &pageSize=100&offset={cursor}
//
// Pagination uses Airtable's `offset` opaque cursor. Tenants without an
// Enterprise audit licence receive 401/403/404 which collapses to
// access.ErrAuditNotAvailable so the worker soft-skips the tenant.
func (c *AirtableAccessConnector) FetchAccessAuditLogs(
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
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("pageSize", "100")
		if !since.IsZero() {
			q.Set("startTime", since.UTC().Format(time.RFC3339))
		}
		if offset != "" {
			q.Set("offset", offset)
		}
		path := "/meta/enterpriseAccount/" + url.PathEscape(cfg.EnterpriseID) + "/auditLogEvents?" + q.Encode()
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
			return fmt.Errorf("airtable: auditLogEvents: status %d: %s", resp.StatusCode, string(body))
		}
		var page airtableAuditPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("airtable: decode audit page: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Events))
		batchMax := cursor
		for i := range page.Events {
			entry := mapAirtableAuditEvent(&page.Events[i])
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
		next := strings.TrimSpace(page.Offset)
		if next == "" {
			return nil
		}
		offset = next
	}
}

type airtableAuditPage struct {
	Events []airtableAuditEvent `json:"events"`
	Offset string               `json:"offset,omitempty"`
}

type airtableAuditEvent struct {
	ID         string `json:"id"`
	Timestamp  string `json:"timestamp"`
	Action     string `json:"action"`
	ActingUser struct {
		ID    string `json:"id,omitempty"`
		Email string `json:"email,omitempty"`
	} `json:"actingUser"`
	Origin struct {
		IPAddress string `json:"ipAddress,omitempty"`
		UserAgent string `json:"userAgent,omitempty"`
	} `json:"origin"`
	ModelType      string                 `json:"modelType,omitempty"`
	ModelID        string                 `json:"modelId,omitempty"`
	ContextDetails map[string]interface{} `json:"contextDetails,omitempty"`
	Payload        map[string]interface{} `json:"payload,omitempty"`
}

func mapAirtableAuditEvent(e *airtableAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseAirtableTime(e.Timestamp)
	if ts.IsZero() {
		return nil
	}
	rawMap := map[string]interface{}{}
	raw, _ := json.Marshal(e)
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        strings.TrimSpace(e.Action),
		Action:           strings.TrimSpace(e.Action),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.ActingUser.ID),
		ActorEmail:       strings.TrimSpace(e.ActingUser.Email),
		TargetExternalID: strings.TrimSpace(e.ModelID),
		TargetType:       strings.TrimSpace(e.ModelType),
		IPAddress:        strings.TrimSpace(e.Origin.IPAddress),
		UserAgent:        strings.TrimSpace(e.Origin.UserAgent),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

// parseAirtableTime parses Airtable's audit-event timestamps. The API
// emits RFC3339 strings with optional millisecond precision.
func parseAirtableTime(s string) time.Time {
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

var _ access.AccessAuditor = (*AirtableAccessConnector)(nil)
