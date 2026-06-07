package crisp

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
	crispAuditPageSize = 100
	crispAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Crisp website operator-event entries
// into the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v1/website/{website_id}/operators/log/list?page=N&search_query=...
//
// Crisp returns events newest-first with a 1-indexed `page` cursor.
// Tenants without operator-log access (no admin scope or self-serve
// plan) receive 401 / 403 / 404, which the connector soft-skips via
// access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *CrispAccessConnector) FetchAccessAuditLogs(
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
	base := fmt.Sprintf("%s/v1/website/%s/operators/log/list",
		c.baseURL(), url.PathEscape(strings.TrimSpace(cfg.WebsiteID)))

	var collected []crispAuditEvent
	for page := 1; page <= crispAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		fullURL := fmt.Sprintf("%s?page=%d", base, page)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("crisp: audit log: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("crisp: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope crispAuditResponse
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("crisp: decode audit log: %w", err)
		}
		olderThanCursor := false
		for i := range envelope.Data {
			ts := parseCrispAuditTime(envelope.Data[i].Stamp)
			if !since.IsZero() && !ts.IsZero() && !ts.After(since) {
				olderThanCursor = true
				continue
			}
			collected = append(collected, envelope.Data[i])
		}
		if olderThanCursor || len(envelope.Data) < crispAuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapCrispAuditEvent(&collected[i])
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

type crispAuditEvent struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Action  string `json:"action"`
	Stamp   int64  `json:"stamp"`
	From    string `json:"from"`
	Subject struct {
		Type      string `json:"type"`
		UserID    string `json:"user_id"`
		Email     string `json:"email"`
		IPAddress string `json:"ip_address"`
	} `json:"subject"`
}

type crispAuditResponse struct {
	Error  bool              `json:"error"`
	Reason string            `json:"reason"`
	Data   []crispAuditEvent `json:"data"`
}

func mapCrispAuditEvent(e *crispAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseCrispAuditTime(e.Stamp)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        strings.TrimSpace(e.Type),
		Action:           strings.TrimSpace(e.Action),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.From),
		ActorEmail:       strings.TrimSpace(e.Subject.Email),
		TargetExternalID: strings.TrimSpace(e.Subject.UserID),
		TargetType:       strings.TrimSpace(e.Subject.Type),
		IPAddress:        strings.TrimSpace(e.Subject.IPAddress),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseCrispAuditTime(stamp int64) time.Time {
	if stamp <= 0 {
		return time.Time{}
	}
	// Crisp stamps are milliseconds since the Unix epoch.
	return time.UnixMilli(stamp).UTC()
}

var _ access.AccessAuditor = (*CrispAccessConnector)(nil)
