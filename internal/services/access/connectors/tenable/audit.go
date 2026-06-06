package tenable

import (
	"context"
	"encoding/json"
	"fmt"
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
// On HTTP 401/403 the connector returns access.ErrAuditNotAvailable
// so callers treat the tenant as plan- or role-gated rather than
// failing the whole sync.
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
		body, err := c.do(req)
		if err != nil {
			if isAuditNotAvailable(err) {
				return access.ErrAuditNotAvailable
			}
			return err
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
		// Stop when the page is short (Tenable returned everything it had),
		// or when the cursor didn't advance (no new events to bump past).
		if len(page.Events) < pageLimit {
			return nil
		}
		if !batchMax.After(cursor) {
			return nil
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

func isAuditNotAvailable(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "status 401") || strings.Contains(msg, "status 403")
}

var _ access.AccessAuditor = (*TenableAccessConnector)(nil)
