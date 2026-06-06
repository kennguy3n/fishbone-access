package netsuite

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

// netsuiteAuditMaxPages bounds systemNote pagination so a misbehaving or
// compromised endpoint that keeps returning hasMore:true cannot loop
// indefinitely, matching the 200-page cap used by every other audit connector.
const netsuiteAuditMaxPages = 200

// FetchAccessAuditLogs streams NetSuite SystemNote audit events into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /record/v1/systemNote?offset={n}&limit=100&date={since}
//
// The handler is called once per provider page in chronological order
// so callers can persist `nextSince` (the newest `date` seen so far)
// as a monotonic cursor. On HTTP 401/403 the connector returns
// access.ErrAuditNotAvailable so callers treat the tenant as plan- or
// role-gated rather than failing the whole sync.
func (c *NetSuiteAccessConnector) FetchAccessAuditLogs(
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
	offset := 0
	base := c.baseURL()
	for pages := 0; pages < netsuiteAuditMaxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("offset", fmt.Sprintf("%d", offset))
		q.Set("limit", "100")
		if !since.IsZero() {
			q.Set("date", since.UTC().Format(time.RFC3339))
		}
		full := base + "/record/v1/systemNote?" + q.Encode()
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
		var page netsuiteSystemNotePage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("netsuite: decode systemNote: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Items))
		batchMax := cursor
		for i := range page.Items {
			entry := mapNetSuiteSystemNote(&page.Items[i])
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
		cursor = batchMax
		if !page.HasMore || len(page.Items) == 0 {
			return nil
		}
		offset += len(page.Items)
	}
	return nil
}

type netsuiteSystemNotePage struct {
	Items   []netsuiteSystemNote `json:"items"`
	HasMore bool                 `json:"hasMore"`
	Offset  int                  `json:"offset"`
	Count   int                  `json:"count"`
}

type netsuiteSystemNote struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Date     string `json:"date"`
	Name     string `json:"name,omitempty"`
	Field    string `json:"field,omitempty"`
	OldValue string `json:"oldValue,omitempty"`
	NewValue string `json:"newValue,omitempty"`
	Record   string `json:"record,omitempty"`
	UserID   string `json:"userId,omitempty"`
}

func mapNetSuiteSystemNote(n *netsuiteSystemNote) *access.AuditLogEntry {
	if n == nil || strings.TrimSpace(n.ID) == "" {
		return nil
	}
	ts, _ := time.Parse(time.RFC3339Nano, n.Date)
	if ts.IsZero() {
		ts, _ = time.Parse(time.RFC3339, n.Date)
	}
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(n)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	eventType := strings.TrimSpace(n.Type)
	if eventType == "" {
		eventType = "system_note"
	}
	return &access.AuditLogEntry{
		EventID:          strings.TrimSpace(n.ID),
		EventType:        eventType,
		Action:           eventType,
		Timestamp:        ts,
		ActorExternalID:  n.UserID,
		ActorEmail:       n.Name,
		TargetExternalID: n.Record,
		TargetType:       n.Field,
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func isAuditNotAvailable(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "status 401") || strings.Contains(msg, "status 403") || strings.Contains(msg, "status 404")
}

var _ access.AccessAuditor = (*NetSuiteAccessConnector)(nil)
