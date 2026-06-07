package stripe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// stripeAuditMaxPages bounds a single sweep to ~20k events. Stripe
// paginates `/v1/events` reverse-chronologically (newest first) via
// `starting_after`, so this only kicks in on the very first sync of a
// long-dormant account; the `created[gte]={since}` filter narrows the
// window on every subsequent run.
const stripeAuditMaxPages = 200

// FetchAccessAuditLogs streams Stripe `/v1/events` records into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v1/events?limit=100&created[gte]={epoch}&starting_after={id}
//
// Stripe's event log is the closest public surface to an audit feed —
// every API and dashboard mutation emits an event. Pagination is
// reverse-chronological: the first page contains the newest events and
// `starting_after` walks backwards in time; `has_more` terminates the
// loop.
//
// The AccessAuditor contract requires that any `nextSince` passed to
// the handler cover only events already yielded — the worker persists
// this cursor even on partial failure (see
// internal/workers/handlers/access_audit.go). To honour the contract
// under reverse-chronological pagination we collect the full sweep
// first, then reverse the entire collection into chronological
// (oldest-first) order and call the handler exactly once with the
// maximum timestamp as `nextSince`. If any page fails mid-sweep (or
// the handler call itself fails) the cursor is never advanced past
// un-yielded events, so a retry replays the same window rather than
// silently skipping older entries below the persisted cursor.
//
// Restricted keys without `rak_read_only` on Events surface as 401/403
// → access.ErrAuditNotAvailable.
func (c *StripeAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL()

	var collected []stripeEvent
	startingAfter := ""
	for page := 0; page < stripeAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", strconv.Itoa(pageSize))
		if !since.IsZero() {
			q.Set("created[gte]", strconv.FormatInt(since.UTC().Unix(), 10))
		}
		if startingAfter != "" {
			q.Set("starting_after", startingAfter)
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"/v1/events?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("stripe: audit events: %w", err)
		}
		body, readErr := readStripeBody(resp)
		if readErr != nil {
			return readErr
		}
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("stripe: audit events: status %d: %s", resp.StatusCode, formatErrorBody(body))
		}
		var pageData stripeEventPage
		if err := json.Unmarshal(body, &pageData); err != nil {
			return fmt.Errorf("stripe: decode events: %w", err)
		}
		if len(pageData.Data) == 0 {
			break
		}
		collected = append(collected, pageData.Data...)
		if !pageData.HasMore {
			break
		}
		startingAfter = pageData.Data[len(pageData.Data)-1].ID
	}

	if len(collected) == 0 {
		return nil
	}

	// Walk the collected events oldest-first so the handler sees a
	// chronologically ascending batch and `nextSince` covers every
	// event we just yielded.
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := len(collected) - 1; i >= 0; i-- {
		entry := mapStripeEvent(&collected[i])
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

type stripeEventPage struct {
	Object  string        `json:"object"`
	HasMore bool          `json:"has_more"`
	Data    []stripeEvent `json:"data"`
}

type stripeEvent struct {
	ID         string          `json:"id"`
	Type       string          `json:"type"`
	Created    int64           `json:"created"`
	APIVersion string          `json:"api_version"`
	Account    string          `json:"account"`
	Data       json.RawMessage `json:"data"`
	Request    struct {
		ID             string `json:"id"`
		IdempotencyKey string `json:"idempotency_key"`
	} `json:"request"`
}

func mapStripeEvent(e *stripeEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	if e.Created <= 0 {
		return nil
	}
	ts := time.Unix(e.Created, 0).UTC()
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        strings.TrimSpace(e.Type),
		Action:           stripeAction(e.Type),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.Account),
		TargetExternalID: strings.TrimSpace(e.Request.ID),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func stripeAction(t string) string {
	t = strings.TrimSpace(t)
	if t == "" {
		return ""
	}
	// Stripe event types are dotted: "customer.created", "account.updated".
	// Surface the trailing verb for quick classification.
	if i := strings.LastIndex(t, "."); i >= 0 && i+1 < len(t) {
		return t[i+1:]
	}
	return t
}

func readStripeBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, errors.New("stripe: empty response")
	}
	defer resp.Body.Close()
	// Match the strict 1 MB cap that newRequest/doRaw apply via
	// io.LimitReader, keeping the audit path consistent with the rest
	// of the connector (and avoiding the up-to-4 KB overshoot of a
	// manual chunked read).
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

var _ access.AccessAuditor = (*StripeAccessConnector)(nil)
