package ovhcloud

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const ovhAuditMaxIDs = 500

// FetchAccessAuditLogs streams OVHcloud "API logs" (call history for
// the current account) into the access audit pipeline. Implements
// access.AccessAuditor.
//
// Endpoint:
//
//	GET /1.0/me/api/logs/self          -> array of opaque log IDs
//	GET /1.0/me/api/logs/self/{id}     -> per-call detail
//
// Authentication uses the OVH application signature scheme (same as
// the rest of this connector). Consumer keys without the
// `/me/api/logs/*` permission receive 401 / 403 / 404 which the
// connector soft-skips via access.ErrAuditNotAvailable.
//
// The endpoint does not natively page; the connector caps the
// per-sweep walk at ovhAuditMaxIDs to keep runs bounded. Entries
// older than the persisted cursor are dropped client-side.
func (c *OVHcloudAccessConnector) FetchAccessAuditLogs(
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

	listURL := c.baseURL(cfg) + "/me/api/logs/self"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, listURL, "")
	if err != nil {
		return err
	}
	resp, err := c.doHTTP(req)
	if err != nil {
		return fmt.Errorf("ovhcloud: audit log list: %w", err)
	}
	body, readErr := readOVHAuditBody(resp)
	if readErr != nil {
		return readErr
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return access.ErrAuditNotAvailable
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("ovhcloud: audit log list: status %d: %s", resp.StatusCode, string(body))
	}
	var ids []json.Number
	if err := json.Unmarshal(body, &ids); err != nil {
		return fmt.Errorf("ovhcloud: decode audit log list: %w", err)
	}
	if len(ids) == 0 {
		return nil
	}
	// The list endpoint returns every retained log ID with no documented
	// ordering, so naively keeping the first ovhAuditMaxIDs could drop the
	// newest events (data loss) if the API happens to return oldest-first.
	// OVH log IDs are monotonically increasing integers, so sort newest-first
	// and keep the most recent ovhAuditMaxIDs, guaranteeing recent events are
	// never discarded ahead of stale ones. Detail fetches below then emit them
	// in chronological (oldest-first) order so the batchMax cursor advances
	// monotonically.
	ids = newestOVHAuditIDs(ids, ovhAuditMaxIDs)

	var collected []ovhAuditEntry
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return err
		}
		detailURL := fmt.Sprintf("%s/me/api/logs/self/%s", c.baseURL(cfg), id.String())
		dreq, err := c.newRequest(ctx, secrets, http.MethodGet, detailURL, "")
		if err != nil {
			return err
		}
		dresp, err := c.doHTTP(dreq)
		if err != nil {
			return fmt.Errorf("ovhcloud: audit log detail: %w", err)
		}
		dbody, readErr := readOVHAuditBody(dresp)
		if readErr != nil {
			return readErr
		}
		if dresp.StatusCode == http.StatusNotFound {
			continue
		}
		if dresp.StatusCode < 200 || dresp.StatusCode >= 300 {
			return fmt.Errorf("ovhcloud: audit log detail: status %d: %s", dresp.StatusCode, string(dbody))
		}
		var entry ovhAuditEntry
		if err := json.Unmarshal(dbody, &entry); err != nil {
			return fmt.Errorf("ovhcloud: decode audit log detail: %w", err)
		}
		if entry.ID == "" {
			entry.ID = id.String()
		}
		ts := parseOVHAuditTime(entry.Date)
		if !since.IsZero() && !ts.IsZero() && !ts.After(since) {
			continue
		}
		collected = append(collected, entry)
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapOVHAuditEntry(&collected[i])
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

type ovhAuditEntry struct {
	ID      string `json:"id,omitempty"`
	Date    string `json:"date"`
	Method  string `json:"method"`
	URL     string `json:"url"`
	Status  int    `json:"status"`
	IP      string `json:"ip"`
	Account string `json:"account"`
}

func mapOVHAuditEntry(e *ovhAuditEntry) *access.AuditLogEntry {
	if e == nil {
		return nil
	}
	if strings.TrimSpace(e.ID) == "" && strings.TrimSpace(e.Date) == "" {
		return nil
	}
	ts := parseOVHAuditTime(e.Date)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	outcome := "success"
	if e.Status >= 400 {
		outcome = "failure"
	}
	action := strings.TrimSpace(e.Method) + " " + strings.TrimSpace(e.URL)
	return &access.AuditLogEntry{
		EventID:         strings.TrimSpace(e.ID),
		EventType:       strings.TrimSpace(e.Method),
		Action:          strings.TrimSpace(action),
		Timestamp:       ts,
		ActorExternalID: strings.TrimSpace(e.Account),
		IPAddress:       strings.TrimSpace(e.IP),
		TargetType:      "api_call",
		Outcome:         outcome,
		RawData:         rawMap,
	}
}

// newestOVHAuditIDs returns at most n log IDs, preferring the most recent
// ones. OVH log IDs are monotonically increasing integers, so the largest
// values are the newest events. The result is ordered ascending (oldest
// first) so the caller fetches and emits entries chronologically, letting the
// audit cursor advance monotonically. If any ID is non-numeric the function
// falls back to a lexical ordering so behaviour stays deterministic.
func newestOVHAuditIDs(ids []json.Number, n int) []json.Number {
	// Pair each ID with its parsed numeric value so the key travels with the
	// value during sorting (avoids the parallel-slice desync bug).
	type idKey struct {
		id  json.Number
		num int64
	}
	keys := make([]idKey, len(ids))
	allNumeric := true
	for i, id := range ids {
		v, err := strconv.ParseInt(strings.TrimSpace(id.String()), 10, 64)
		if err != nil {
			allNumeric = false
		}
		keys[i] = idKey{id: id, num: v}
	}

	sort.SliceStable(keys, func(i, j int) bool {
		if allNumeric {
			return keys[i].num < keys[j].num
		}
		return keys[i].id.String() < keys[j].id.String()
	})

	// Keep the newest n (the tail of the ascending slice) while preserving
	// ascending order for chronological emission.
	if n > 0 && len(keys) > n {
		keys = keys[len(keys)-n:]
	}
	out := make([]json.Number, len(keys))
	for i := range keys {
		out[i] = keys[i].id
	}
	return out
}

func parseOVHAuditTime(s string) time.Time {
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
	if ts, err := time.Parse("2006-01-02T15:04:05", s); err == nil {
		return ts.UTC()
	}
	return time.Time{}
}

func readOVHAuditBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, errors.New("ovhcloud: empty response")
	}
	defer resp.Body.Close()
	const max = 1 << 20
	return io.ReadAll(io.LimitReader(resp.Body, max))
}

var _ access.AccessAuditor = (*OVHcloudAccessConnector)(nil)
