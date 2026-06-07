package splunk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/access/httputil"
)

const (
	splunkAuditPageSize = 100
	splunkAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Splunk Cloud audit events into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint (Splunk Cloud / Enterprise):
//
//	GET /services/audit/events?output_mode=json&count=100&offset=N&search={spl}
//
// Authentication is the Splunk bearer token (same as the existing
// users endpoint). Tenants without admin / sc_admin entitlement or
// without the audit search head receive 401 / 403 / 404 which the
// connector soft-skips via access.ErrAuditNotAvailable.
//
// The endpoint exposes a feed-style envelope with a top-level
// `entry` array plus pagination metadata in `paging` /
// `messages`. To honour the AccessAuditor contract the connector
// buffers every page before advancing the persisted cursor: if any
// page fails the cursor stays where it was, so a retry replays the
// same window rather than silently skipping older entries below
// the persisted cursor.
func (c *SplunkAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL(cfg) + "/services/audit/events"

	var collected []splunkAuditEntry
	offset := 0
	for pages := 0; pages < splunkAuditMaxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("output_mode", "json")
		q.Set("count", fmt.Sprintf("%d", splunkAuditPageSize))
		q.Set("offset", fmt.Sprintf("%d", offset))
		if !since.IsZero() {
			q.Set("search", fmt.Sprintf("earliest=%d", since.UTC().Unix()))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("splunk: audit events: %w", err)
		}
		body, readErr := readSplunkBody(resp)
		if readErr != nil {
			return readErr
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("splunk: audit events: status %d: %s", resp.StatusCode, httputil.SafeErrorBody(body))
		}
		var p splunkAuditPage
		if err := json.Unmarshal(body, &p); err != nil {
			return fmt.Errorf("splunk: decode audit events: %w", err)
		}
		collected = append(collected, p.Entry...)
		if len(p.Entry) < splunkAuditPageSize {
			break
		}
		offset += len(p.Entry)
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapSplunkAuditEntry(&collected[i])
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

type splunkAuditPage struct {
	Entry  []splunkAuditEntry `json:"entry"`
	Paging struct {
		Total  int `json:"total"`
		Offset int `json:"offset"`
	} `json:"paging"`
}

type splunkAuditEntry struct {
	Name      string `json:"name"`
	Published string `json:"published"`
	Updated   string `json:"updated"`
	Content   struct {
		Action     string `json:"action"`
		Info       string `json:"info"`
		Object     string `json:"object"`
		ObjectType string `json:"object_type"`
		Operation  string `json:"operation"`
		Raw        string `json:"_raw"`
		Time       string `json:"_time"`
		User       string `json:"user"`
		Host       string `json:"host"`
	} `json:"content"`
}

func mapSplunkAuditEntry(e *splunkAuditEntry) *access.AuditLogEntry {
	if e == nil {
		return nil
	}
	ts := parseSplunkAuditTime(firstNonEmptySplunk(e.Content.Time, e.Published, e.Updated))
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	id := strings.TrimSpace(e.Name)
	if id == "" {
		id = fmt.Sprintf("%s/%s/%s", strings.TrimSpace(e.Content.Action),
			strings.TrimSpace(e.Content.Time), strings.TrimSpace(e.Content.Object))
	}
	action := strings.TrimSpace(e.Content.Action)
	if action == "" {
		action = strings.TrimSpace(e.Content.Operation)
	}
	return &access.AuditLogEntry{
		EventID:          id,
		EventType:        action,
		Action:           action,
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.Content.User),
		TargetExternalID: strings.TrimSpace(e.Content.Object),
		TargetType:       strings.TrimSpace(e.Content.ObjectType),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseSplunkAuditTime(s string) time.Time {
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
	// Splunk sometimes uses "2006-01-02 15:04:05.000 -0700" — strip TZ.
	if ts, err := time.Parse("2006-01-02 15:04:05.000 -0700", s); err == nil {
		return ts.UTC()
	}
	return time.Time{}
}

func firstNonEmptySplunk(vs ...string) string {
	for _, v := range vs {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// readSplunkBody reads up to splunkBodyReadCap bytes from resp.Body,
// matching the strict 1 MB cap that do() uses via io.LimitReader.
// The earlier chunked implementation could overshoot by up to one
// 4 KB tmp buffer (~max + 4 KB) before the post-append guard tripped,
// which is harmless in practice but produced a subtle divergence from
// do()'s strict bound. Using io.LimitReader here keeps the audit path
// byte-for-byte consistent with the rest of the connector.
const splunkBodyReadCap = 1 << 20

func readSplunkBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, errors.New("splunk: empty response")
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, splunkBodyReadCap))
}

var _ access.AccessAuditor = (*SplunkAccessConnector)(nil)
