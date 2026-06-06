package gusto

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
	gustoAuditPageSize = 100
	gustoAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Gusto company-event audit entries into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v1/companies/{company_id}/events?page=N&per=100
//
// Gusto returns events newest-first. Tenants without `events` scope
// (or on plans without audit-trail visibility) receive 401 / 403 / 404,
// which the connector soft-skips via access.ErrAuditNotAvailable per
// docs/architecture.md §2.
func (c *GustoAccessConnector) FetchAccessAuditLogs(
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
	base := fmt.Sprintf("%s/v1/companies/%s/events",
		c.baseURL(), url.PathEscape(strings.TrimSpace(cfg.CompanyID)))

	var collected []gustoAuditEvent
	for page := 1; page <= gustoAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		fullURL := fmt.Sprintf("%s?page=%d&per=%d", base, page, gustoAuditPageSize)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("gusto: audit log: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("gusto: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var events []gustoAuditEvent
		if err := json.Unmarshal(body, &events); err != nil {
			return fmt.Errorf("gusto: decode audit log: %w", err)
		}
		olderThanCursor := false
		for i := range events {
			ts := parseGustoAuditTime(events[i].OccurredAt)
			if !since.IsZero() && !ts.IsZero() && !ts.After(since) {
				olderThanCursor = true
				continue
			}
			collected = append(collected, events[i])
		}
		if olderThanCursor || len(events) < gustoAuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapGustoAuditEvent(&collected[i])
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

type gustoAuditEvent struct {
	UUID         string `json:"uuid"`
	EventType    string `json:"event_type"`
	OccurredAt   string `json:"occurred_at"`
	ActorType    string `json:"actor_type"`
	ActorUUID    string `json:"actor_uuid"`
	ActorEmail   string `json:"actor_email"`
	ResourceType string `json:"resource_type"`
	ResourceUUID string `json:"resource_uuid"`
	IPAddress    string `json:"ip_address"`
}

func mapGustoAuditEvent(e *gustoAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.UUID) == "" {
		return nil
	}
	ts := parseGustoAuditTime(e.OccurredAt)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          e.UUID,
		EventType:        strings.TrimSpace(e.EventType),
		Action:           strings.TrimSpace(e.EventType),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.ActorUUID),
		ActorEmail:       strings.TrimSpace(e.ActorEmail),
		TargetExternalID: strings.TrimSpace(e.ResourceUUID),
		TargetType:       strings.TrimSpace(e.ResourceType),
		IPAddress:        strings.TrimSpace(e.IPAddress),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseGustoAuditTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
