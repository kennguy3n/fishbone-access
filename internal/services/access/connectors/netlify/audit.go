package netlify

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

const (
	netlifyAuditPageSize = 100
	netlifyAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Netlify "audit log" events into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /api/v1/accounts/{account_slug}/audit?page=N&per_page=100
//
// Netlify audit log access is restricted to Business plan accounts;
// other tenants receive 401 / 403 / 404 which the connector
// soft-skips via access.ErrAuditNotAvailable.
//
// The endpoint returns entries newest-first and uses simple page/per_page
// pagination. The connector buffers every page before invoking the
// handler so a partial sweep does not advance the persisted cursor.
func (c *NetlifyAccessConnector) FetchAccessAuditLogs(
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
	base := "/api/v1/accounts/" + url.PathEscape(cfg.AccountSlug) + "/audit"

	var collected []netlifyAuditEvent
	page := 1
	for pages := 0; pages < netlifyAuditMaxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("per_page", fmt.Sprintf("%d", netlifyAuditPageSize))
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("netlify: audit log: %w", err)
		}
		body, readErr := readNetlifyAuditBody(resp)
		if readErr != nil {
			return readErr
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusPaymentRequired:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("netlify: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var events []netlifyAuditEvent
		if err := json.Unmarshal(body, &events); err != nil {
			return fmt.Errorf("netlify: decode audit log: %w", err)
		}
		olderThanCursor := false
		for i := range events {
			ts := parseNetlifyAuditTime(events[i].CreatedAt)
			if !since.IsZero() && !ts.IsZero() && !ts.After(since) {
				olderThanCursor = true
				continue
			}
			collected = append(collected, events[i])
		}
		if olderThanCursor || len(events) < netlifyAuditPageSize {
			break
		}
		page++
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapNetlifyAuditEvent(&collected[i])
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

type netlifyAuditEvent struct {
	ID        string `json:"id"`
	AccountID string `json:"account_id"`
	Action    string `json:"action"`
	ActorID   string `json:"actor_id"`
	ActorName string `json:"actor_name"`
	ActorType string `json:"actor_type"`
	LogType   string `json:"log_type"`
	CreatedAt string `json:"created_at"`
	Payload   struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"payload"`
}

func mapNetlifyAuditEvent(e *netlifyAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseNetlifyAuditTime(e.CreatedAt)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        strings.TrimSpace(e.LogType),
		Action:           strings.TrimSpace(e.Action),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.ActorID),
		ActorEmail:       strings.TrimSpace(e.Payload.Email),
		TargetExternalID: strings.TrimSpace(e.Payload.ID),
		TargetType:       strings.TrimSpace(e.LogType),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseNetlifyAuditTime(s string) time.Time {
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

func readNetlifyAuditBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, errors.New("netlify: empty response")
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

var _ access.AccessAuditor = (*NetlifyAccessConnector)(nil)
