package front

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// FetchAccessAuditLogs streams Front events into the access audit
// pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /events?q[after]={unix}&limit=100
//
// Pagination uses Front's `_pagination.next` absolute URL pointer; the
// loop follows it verbatim until empty. Tenants without an event-stream
// scope receive 401/403/404 which collapses to access.ErrAuditNotAvailable
// so the worker soft-skips the tenant rather than looping.
func (c *FrontAccessConnector) FetchAccessAuditLogs(
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
	cursor := since

	q := url.Values{}
	q.Set("limit", "100")
	if !since.IsZero() {
		q.Set("q[after]", strconv.FormatInt(since.UTC().Unix(), 10))
	}
	nextURL := c.baseURL() + "/events?" + q.Encode()

	for nextURL != "" {
		if err := ctx.Err(); err != nil {
			return err
		}
		next, batch, batchMax, terminate, err := c.fetchFrontPage(ctx, secrets, nextURL, cursor)
		if err != nil {
			return err
		}
		if err := handler(batch, batchMax, access.DefaultAuditPartition); err != nil {
			return err
		}
		cursor = batchMax
		if terminate {
			return nil
		}
		nextURL = next
	}
	return nil
}

func (c *FrontAccessConnector) fetchFrontPage(
	ctx context.Context, secrets Secrets, pageURL string, cursor time.Time,
) (string, []*access.AuditLogEntry, time.Time, bool, error) {
	req, err := c.newRequest(ctx, secrets, http.MethodGet, pageURL)
	if err != nil {
		return "", nil, cursor, true, err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return "", nil, cursor, true, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return "", nil, cursor, true, access.ErrAuditNotAvailable
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", nil, cursor, true, fmt.Errorf("front: events: status %d: %s", resp.StatusCode, string(body))
	}
	var page frontEventPage
	if err := json.Unmarshal(body, &page); err != nil {
		return "", nil, cursor, true, fmt.Errorf("front: decode events page: %w", err)
	}
	batch := make([]*access.AuditLogEntry, 0, len(page.Results))
	batchMax := cursor
	for i := range page.Results {
		entry := mapFrontEvent(&page.Results[i])
		if entry == nil {
			continue
		}
		if entry.Timestamp.After(batchMax) {
			batchMax = entry.Timestamp
		}
		batch = append(batch, entry)
	}
	terminate := strings.TrimSpace(page.Pagination.Next) == ""
	return strings.TrimSpace(page.Pagination.Next), batch, batchMax, terminate, nil
}

type frontEventPage struct {
	Results    []frontEvent    `json:"_results"`
	Pagination frontPagination `json:"_pagination"`
}

type frontEvent struct {
	ID        string  `json:"id"`
	Type      string  `json:"type"`
	EmittedAt float64 `json:"emitted_at"`
	Source    struct {
		Data map[string]interface{} `json:"_data,omitempty"`
		Meta map[string]interface{} `json:"_meta,omitempty"`
	} `json:"source"`
	Target struct {
		Data map[string]interface{} `json:"_data,omitempty"`
		Meta map[string]interface{} `json:"_meta,omitempty"`
	} `json:"target"`
}

func mapFrontEvent(e *frontEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := time.UnixMilli(int64(e.EmittedAt * 1000)).UTC()
	if e.EmittedAt == 0 {
		ts = time.Time{}
	}
	rawMap := map[string]interface{}{}
	raw, _ := json.Marshal(e)
	_ = json.Unmarshal(raw, &rawMap)
	actorID, actorEmail := frontExtractActor(e.Source.Data)
	targetID, targetType := frontExtractTarget(e.Target.Data, e.Target.Meta)
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        strings.TrimSpace(e.Type),
		Action:           strings.TrimSpace(e.Type),
		Timestamp:        ts,
		ActorExternalID:  actorID,
		ActorEmail:       actorEmail,
		TargetExternalID: targetID,
		TargetType:       targetType,
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func frontExtractActor(data map[string]interface{}) (string, string) {
	if data == nil {
		return "", ""
	}
	id, _ := data["id"].(string)
	email, _ := data["email"].(string)
	return id, email
}

func frontExtractTarget(data, meta map[string]interface{}) (string, string) {
	if data == nil && meta == nil {
		return "", ""
	}
	var id string
	if data != nil {
		if v, ok := data["id"].(string); ok {
			id = v
		}
	}
	var typ string
	if meta != nil {
		if v, ok := meta["type"].(string); ok {
			typ = v
		}
	}
	return id, typ
}

var _ access.AccessAuditor = (*FrontAccessConnector)(nil)
