package shopify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// FetchAccessAuditLogs streams Shopify Admin `/events.json` records
// into the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /admin/api/2024-01/events.json?limit=250&created_at_min={iso}&since_id={n}
//
// Shopify's events feed is the closest public surface for shop-level
// audit (verb + subject pairs like `users created`, `customer updated`).
// True dashboard staff-audit logs require Shopify Plus + the Shop
// Activity API; non-Plus shops return 403 on that endpoint, which we
// soft-skip via access.ErrAuditNotAvailable. The Events API is
// available on every plan and is the most widely deployed surface, so
// the connector consumes it as the canonical audit feed.
//
// Pagination uses `since_id` because the events endpoint orders by id
// ascending; combined with `created_at_min` the connector resumes
// incrementally from the last persisted timestamp.
func (c *ShopifyAccessConnector) FetchAccessAuditLogs(
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
	cursor := since
	sinceID := int64(0)
	base := c.baseURL(cfg) + "/admin/api/2024-01/events.json"
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", "250")
		if !since.IsZero() {
			q.Set("created_at_min", since.UTC().Format(time.RFC3339))
		}
		if sinceID > 0 {
			q.Set("since_id", fmt.Sprintf("%d", sinceID))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("shopify: events: %w", err)
		}
		body, readErr := readShopifyBody(resp)
		if readErr != nil {
			return readErr
		}
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("shopify: events: status %d: %s", resp.StatusCode, string(body))
		}
		var page shopifyEventsPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("shopify: decode events: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Events))
		batchMax := cursor
		lastID := int64(0)
		for i := range page.Events {
			entry := mapShopifyEvent(&page.Events[i])
			if entry == nil {
				continue
			}
			if entry.Timestamp.After(batchMax) {
				batchMax = entry.Timestamp
			}
			batch = append(batch, entry)
			if page.Events[i].ID > lastID {
				lastID = page.Events[i].ID
			}
		}
		if err := handler(batch, batchMax, access.DefaultAuditPartition); err != nil {
			return err
		}
		cursor = batchMax
		if lastID == 0 || len(page.Events) < 250 {
			return nil
		}
		sinceID = lastID
	}
}

type shopifyEventsPage struct {
	Events []shopifyEvent `json:"events"`
}

type shopifyEvent struct {
	ID          int64  `json:"id"`
	SubjectID   int64  `json:"subject_id"`
	SubjectType string `json:"subject_type"`
	Verb        string `json:"verb"`
	Arguments   []any  `json:"arguments,omitempty"`
	Body        string `json:"body,omitempty"`
	Message     string `json:"message,omitempty"`
	Author      string `json:"author,omitempty"`
	Description string `json:"description,omitempty"`
	CreatedAt   string `json:"created_at"`
}

func mapShopifyEvent(e *shopifyEvent) *access.AuditLogEntry {
	if e == nil || e.ID == 0 {
		return nil
	}
	ts := parseShopifyTime(e.CreatedAt)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	eventType := strings.TrimSpace(e.SubjectType)
	if v := strings.TrimSpace(e.Verb); v != "" {
		eventType = eventType + "." + v
	}
	return &access.AuditLogEntry{
		EventID:          fmt.Sprintf("%d", e.ID),
		EventType:        eventType,
		Action:           strings.TrimSpace(e.Verb),
		Timestamp:        ts,
		ActorEmail:       strings.TrimSpace(e.Author),
		TargetExternalID: fmt.Sprintf("%d", e.SubjectID),
		TargetType:       strings.TrimSpace(e.SubjectType),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseShopifyTime(s string) time.Time {
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

func readShopifyBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, errors.New("shopify: empty response")
	}
	defer resp.Body.Close()
	const max = 1 << 20
	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if len(buf) >= max {
				break
			}
		}
		if err != nil {
			break
		}
	}
	return buf, nil
}

var _ access.AccessAuditor = (*ShopifyAccessConnector)(nil)
