package xero

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
	xeroAuditPageSize = 100
	xeroAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Xero journal-history events (a proxy for
// audit activity) into the access audit pipeline. Implements
// access.AccessAuditor.
//
// Endpoint:
//
//	GET /api.xro/2.0/Journals?offset=N
//	with `Xero-Tenant-Id` header.
//
// Bearer-token auth. Tenants without the audit-trail entitlement return
// 401 / 403 / 404, soft-skipped via access.ErrAuditNotAvailable.
func (c *XeroAccessConnector) FetchAccessAuditLogs(
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

	var collected []xeroJournal
	offset := int64(0)
	for page := 0; page < xeroAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		if offset > 0 {
			q.Set("offset", fmt.Sprintf("%d", offset))
		}
		if !since.IsZero() {
			q.Set("ModifiedAfter", since.UTC().Format(time.RFC3339))
		}
		fullURL := c.baseURL() + "/api.xro/2.0/Journals"
		if encoded := q.Encode(); encoded != "" {
			fullURL += "?" + encoded
		}
		req, err := c.newRequest(ctx, cfg, secrets, http.MethodGet, fullURL)
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("xero: audit log: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("xero: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope struct {
			Journals []xeroJournal `json:"Journals"`
		}
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("xero: decode audit log: %w", err)
		}
		if len(envelope.Journals) == 0 {
			break
		}
		for i := range envelope.Journals {
			collected = append(collected, envelope.Journals[i])
			if envelope.Journals[i].JournalNumber > offset {
				offset = envelope.Journals[i].JournalNumber
			}
		}
		if len(envelope.Journals) < xeroAuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapXeroJournal(&collected[i])
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

type xeroJournal struct {
	JournalID      string `json:"JournalID"`
	JournalNumber  int64  `json:"JournalNumber"`
	JournalDate    string `json:"JournalDate"`
	CreatedDateUTC string `json:"CreatedDateUTC"`
	Reference      string `json:"Reference"`
	SourceID       string `json:"SourceID"`
	SourceType     string `json:"SourceType"`
}

func mapXeroJournal(e *xeroJournal) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.JournalID) == "" {
		return nil
	}
	ts := parseXeroAuditTime(e.CreatedDateUTC)
	if ts.IsZero() {
		ts = parseXeroAuditTime(e.JournalDate)
	}
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          e.JournalID,
		EventType:        "journal.posted",
		Action:           "posted",
		Timestamp:        ts,
		TargetExternalID: strings.TrimSpace(e.SourceID),
		TargetType:       strings.TrimSpace(e.SourceType),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseXeroAuditTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if strings.HasPrefix(s, "/Date(") {
		end := strings.IndexByte(s[6:], ')')
		if end > 0 {
			ms := s[6 : 6+end]
			plus := strings.IndexAny(ms, "+-")
			if plus > 0 {
				ms = ms[:plus]
			}
			var n int64
			_, _ = fmt.Sscanf(ms, "%d", &n)
			if n > 0 {
				return time.UnixMilli(n).UTC()
			}
		}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
