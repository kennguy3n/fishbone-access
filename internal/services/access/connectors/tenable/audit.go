package tenable

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

// FetchAccessAuditLogs streams Tenable.io audit events into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /audit-log/v1/events?f=date.gt:{since}&sort=received_asc&limit=1000
//
// Tenable's audit-log endpoint returns up to 1000 events per call and
// does not expose cursor-based pagination — instead callers advance
// the `f=date.gt:{since}` filter past the newest event in the previous
// batch. To drain backlogs larger than the 1000-event page size on a
// single sync this loop keeps requesting in `sort=received_asc` order
// and bumps `date.gt` to the newest `received` timestamp seen on each
// page until a partial page (or empty page) signals the queue is
// drained. The handler is invoked once per provider page in
// chronological order so callers can persist `nextSince` (the newest
// `received` timestamp) as a monotonic cursor.
//
// On HTTP 401/403/404 the connector returns access.ErrAuditNotAvailable
// so callers treat the tenant as plan- or role-gated rather than
// failing the whole sync. (Tenable returns 404 when the audit-log
// endpoint is not enabled for the tenant's plan tier, so it must be
// soft-skipped like 401/403.) The status is read directly off the
// response — not parsed out of an error string — so it stays correct
// regardless of error-formatting changes, matching every other audit
// connector in this package set.
func (c *TenableAccessConnector) FetchAccessAuditLogs(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	sincePartitions map[string]time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	const pageLimit = 1000
	since := sincePartitions[access.DefaultAuditPartition]
	cursor := since
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", fmt.Sprintf("%d", pageLimit))
		q.Set("sort", "received_asc")
		if !cursor.IsZero() {
			q.Set("f", "date.gt:"+cursor.UTC().Format("2006-01-02T15:04:05"))
		}
		full := c.baseURL() + "/audit-log/v1/events?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, full)
		if err != nil {
			return err
		}
		resp, err := c.doRaw(req)
		if err != nil {
			return err
		}
		status := resp.StatusCode
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch {
		case status == http.StatusUnauthorized ||
			status == http.StatusForbidden ||
			status == http.StatusNotFound:
			// Audit-log access is plan- or role-gated; soft-skip.
			return access.ErrAuditNotAvailable
		case status < 200 || status >= 300:
			return fmt.Errorf("tenable: audit GET %s: status %d: %s", req.URL.Path, status, string(body))
		}
		var page tenableAuditPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("tenable: decode events: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Events))
		batchMax := cursor
		for i := range page.Events {
			entry := mapTenableEvent(&page.Events[i])
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
		// A short page means Tenable returned everything it had — the
		// queue is drained, so we're done.
		if len(page.Events) < pageLimit {
			return nil
		}
		// A full page that does not advance the watermark cannot be
		// paged past: the only pagination lever is `date.gt:{received}`,
		// so if every event on a full page mapped to a timestamp at or
		// before the current cursor (e.g. more than pageLimit events
		// share the same second, or all `received` values were
		// unparseable), bumping `date.gt` would re-request this exact
		// page forever. Returning nil here would report a false-complete
		// drain AND persist an unchanged cursor, permanently stalling the
		// audit stream and silently dropping every later event. Surface
		// it as an error so the sync is retried/alerted instead.
		if !batchMax.After(cursor) {
			return fmt.Errorf(
				"tenable: audit pagination stalled at %s: a full page of %d events did not advance the cursor",
				cursor.UTC().Format(time.RFC3339), pageLimit)
		}
		cursor = batchMax
	}
}

type tenableAuditPage struct {
	Events []tenableEvent `json:"events"`
}

type tenableEvent struct {
	ID         string                 `json:"id"`
	Action     string                 `json:"action"`
	CRUD       string                 `json:"crud"`
	IsAnon     bool                   `json:"is_anonymous"`
	IsFailure  bool                   `json:"is_failure"`
	Received   string                 `json:"received"`
	Actor      tenableEventActor      `json:"actor"`
	Target     tenableEventTarget     `json:"target"`
	Fields     []tenableEventField    `json:"fields"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
}

type tenableEventActor struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type tenableEventTarget struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
}

type tenableEventField struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func mapTenableEvent(e *tenableEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.Received) == "" {
		return nil
	}
	ts, _ := time.Parse(time.RFC3339Nano, e.Received)
	if ts.IsZero() {
		ts, _ = time.Parse(time.RFC3339, e.Received)
	}
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	outcome := "success"
	if e.IsFailure {
		outcome = "failure"
	}
	ip := ""
	for _, f := range e.Fields {
		if strings.EqualFold(f.Key, "X-Forwarded-For") || strings.EqualFold(f.Key, "ip") {
			ip = f.Value
			break
		}
	}
	return &access.AuditLogEntry{
		EventID:          strings.TrimSpace(e.ID),
		EventType:        strings.TrimSpace(e.Action),
		Action:           strings.TrimSpace(e.CRUD),
		Timestamp:        ts,
		ActorExternalID:  e.Actor.ID,
		ActorEmail:       e.Actor.Name,
		TargetExternalID: e.Target.ID,
		TargetType:       e.Target.Type,
		IPAddress:        ip,
		Outcome:          outcome,
		RawData:          rawMap,
	}
}

var _ access.AccessAuditor = (*TenableAccessConnector)(nil)
