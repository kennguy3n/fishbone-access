package bigcommerce

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
	bcAuditPageSize = 100
	bcAuditMaxPages = 200
)

// FetchAccessAuditLogs streams BigCommerce Store Logs entries into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /stores/{store_hash}/v2/store/systemlogs?page=N&limit=100&min_date_created={iso}
//
// The Store Logs API requires the X-Auth-Token already supplied to
// the connector; lower-scope tokens surface 401/403/404 which the
// connector soft-skips via access.ErrAuditNotAvailable per
// docs/architecture.md §2.
func (c *BigCommerceAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL() + "/stores/" + url.PathEscape(cfg.StoreHash) + "/v2/store/systemlogs"

	var collected []bcSystemLogEntry
	for page := 1; page <= bcAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("limit", fmt.Sprintf("%d", bcAuditPageSize))
		if !since.IsZero() {
			q.Set("min_date_created", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("bigcommerce: audit: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		case http.StatusNoContent:
			// No more pages — stop pagination cleanly.
			return emitBigCommerceAuditBatch(collected, since, handler)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("bigcommerce: audit: status %d: %s", resp.StatusCode, string(body))
		}
		if len(body) == 0 {
			break
		}
		var entries []bcSystemLogEntry
		if err := json.Unmarshal(body, &entries); err != nil {
			return fmt.Errorf("bigcommerce: decode audit: %w", err)
		}
		collected = append(collected, entries...)
		if len(entries) < bcAuditPageSize {
			break
		}
	}

	return emitBigCommerceAuditBatch(collected, since, handler)
}

// emitBigCommerceAuditBatch converts the collected systemlog rows into
// access.AuditLogEntry batches and invokes the handler with the
// high-watermark timestamp. Returns nil without invoking the handler
// when there is nothing to emit.
func emitBigCommerceAuditBatch(
	collected []bcSystemLogEntry,
	since time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapBigCommerceSystemLog(&collected[i])
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

type bcSystemLogEntry struct {
	ID          json.Number `json:"id"`
	StaffID     json.Number `json:"staff_id"`
	Section     string      `json:"section"`
	Title       string      `json:"title"`
	Message     string      `json:"message"`
	IPAddress   string      `json:"ip_address"`
	DateCreated string      `json:"date_created"`
	Country     string      `json:"country"`
}

func mapBigCommerceSystemLog(e *bcSystemLogEntry) *access.AuditLogEntry {
	if e == nil {
		return nil
	}
	ts, err := time.Parse(time.RFC3339, strings.TrimSpace(e.DateCreated))
	if err != nil {
		// Fall back to RFC1123Z which BigCommerce sometimes uses.
		ts, err = time.Parse(time.RFC1123Z, strings.TrimSpace(e.DateCreated))
		if err != nil {
			return nil
		}
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:         strings.TrimSpace(e.ID.String()),
		EventType:       strings.TrimSpace(e.Section),
		Action:          strings.TrimSpace(e.Title),
		Timestamp:       ts.UTC(),
		ActorExternalID: strings.TrimSpace(e.StaffID.String()),
		IPAddress:       strings.TrimSpace(e.IPAddress),
		Outcome:         "success",
		RawData:         rawMap,
	}
}

var _ access.AccessAuditor = (*BigCommerceAccessConnector)(nil)
