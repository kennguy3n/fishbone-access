package gorgias

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
	gorgiasAuditPageSize = 100
	gorgiasAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Gorgias /api/account-events entries
// into the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /api/account-events?page=N&per_page=100
//
// Tenants without account-event scope receive 401 / 403 / 404, which
// the connector soft-skips via access.ErrAuditNotAvailable per
// docs/architecture.md §2.
func (c *GorgiasAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL(cfg) + "/api/account-events"

	var collected []gorgiasAuditEvent
	for page := 1; page <= gorgiasAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("per_page", fmt.Sprintf("%d", gorgiasAuditPageSize))
		req, err := c.newRequest(ctx, cfg, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("gorgias: audit log: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("gorgias: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope gorgiasAuditResponse
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("gorgias: decode audit log: %w", err)
		}
		olderThanCursor := false
		for i := range envelope.Data {
			ts := parseGorgiasAuditTime(envelope.Data[i].Created)
			if !since.IsZero() && !ts.IsZero() && !ts.After(since) {
				olderThanCursor = true
				continue
			}
			collected = append(collected, envelope.Data[i])
		}
		if olderThanCursor || len(envelope.Data) < gorgiasAuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapGorgiasAuditEvent(&collected[i])
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

type gorgiasAuditEvent struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Action      string `json:"action"`
	Created     string `json:"created_datetime"`
	UserID      string `json:"user_id"`
	UserEmail   string `json:"user_email"`
	IPAddress   string `json:"ip_address"`
	Description string `json:"description"`
}

type gorgiasAuditResponse struct {
	Data []gorgiasAuditEvent `json:"data"`
	Meta struct {
		Page    int `json:"page"`
		PerPage int `json:"per_page"`
		Total   int `json:"total"`
	} `json:"meta"`
}

func mapGorgiasAuditEvent(e *gorgiasAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseGorgiasAuditTime(e.Created)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:         e.ID,
		EventType:       strings.TrimSpace(e.Type),
		Action:          strings.TrimSpace(e.Action),
		Timestamp:       ts,
		ActorExternalID: strings.TrimSpace(e.UserID),
		ActorEmail:      strings.TrimSpace(e.UserEmail),
		IPAddress:       strings.TrimSpace(e.IPAddress),
		Outcome:         "success",
		RawData:         rawMap,
	}
}

func parseGorgiasAuditTime(s string) time.Time {
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
