package deel

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
	deelAuditPageSize = 100
	deelAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Deel audit-trail entries into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /rest/v2/audit-logs?page=N&page_size=100&created_at__gte=<RFC3339>
//
// Bearer-token auth. Tenants without the audit-trail entitlement return
// 401 / 403 / 404, soft-skipped via access.ErrAuditNotAvailable.
func (c *DeelAccessConnector) FetchAccessAuditLogs(
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

	var collected []deelAuditEntry
	for page := 1; page <= deelAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("page_size", fmt.Sprintf("%d", deelAuditPageSize))
		if !since.IsZero() {
			q.Set("created_at__gte", since.UTC().Format(time.RFC3339))
		}
		fullURL := c.baseURL() + "/rest/v2/audit-logs?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("deel: audit log: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("deel: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope struct {
			Data []deelAuditEntry `json:"data"`
		}
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("deel: decode audit log: %w", err)
		}
		olderThanCursor := false
		for i := range envelope.Data {
			ts := parseDeelAuditTime(envelope.Data[i].CreatedAt)
			if !since.IsZero() && !ts.IsZero() && !ts.After(since) {
				olderThanCursor = true
				continue
			}
			collected = append(collected, envelope.Data[i])
		}
		if olderThanCursor || len(envelope.Data) < deelAuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapDeelAuditEntry(&collected[i])
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

type deelAuditEntry struct {
	ID         string `json:"id"`
	Action     string `json:"action"`
	EntityType string `json:"entity_type"`
	EntityID   string `json:"entity_id"`
	CreatedAt  string `json:"created_at"`
	ActorID    string `json:"actor_id"`
	ActorEmail string `json:"actor_email"`
	IP         string `json:"ip"`
	Status     string `json:"status"`
}

func mapDeelAuditEntry(e *deelAuditEntry) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseDeelAuditTime(e.CreatedAt)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        strings.TrimSpace(e.Action),
		Action:           strings.TrimSpace(e.Action),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.ActorID),
		ActorEmail:       strings.TrimSpace(e.ActorEmail),
		TargetExternalID: strings.TrimSpace(e.EntityID),
		TargetType:       strings.TrimSpace(e.EntityType),
		IPAddress:        strings.TrimSpace(e.IP),
		Outcome:          strings.TrimSpace(e.Status),
		RawData:          rawMap,
	}
}

func parseDeelAuditTime(s string) time.Time {
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

var _ access.AccessAuditor = (*DeelAccessConnector)(nil)
