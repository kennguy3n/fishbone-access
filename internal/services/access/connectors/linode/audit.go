package linode

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
	"github.com/kennguy3n/fishbone-access/internal/services/access/connectors/connutil"
)

const (
	linodeAuditPageSize = 100
	linodeAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Linode account "events" (audit log)
// into the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v4/account/events?page=N&page_size=100
//
// Linode account events require the `account:read_only` (or
// `events:read_only`) OAuth scope. Tokens without the scope receive
// 401 / 403 / 404 which the connector soft-skips via
// access.ErrAuditNotAvailable.
//
// Events are returned newest-first; the connector pages until it
// finds an event older than the persisted cursor, buffers the
// remainder, and then invokes the handler exactly once with the
// final batch and the new monotonic cursor.
func (c *LinodeAccessConnector) FetchAccessAuditLogs(
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

	var collected []linodeAuditEvent
	page := 1
	for pages := 0; pages < linodeAuditMaxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("page_size", fmt.Sprintf("%d", linodeAuditPageSize))
		req, err := c.newRequest(ctx, secrets, http.MethodGet,
			c.baseURL()+"/v4/account/events?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("linode: audit log: %w", err)
		}
		body, readErr := readLinodeAuditBody(resp)
		if readErr != nil {
			return readErr
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("linode: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var parsed linodeAuditResponse
		if err := json.Unmarshal(body, &parsed); err != nil {
			return fmt.Errorf("linode: decode audit log: %w", err)
		}
		olderThanCursor := false
		for i := range parsed.Data {
			ts := parseLinodeAuditTime(parsed.Data[i].Created)
			if !since.IsZero() && !ts.IsZero() && !ts.After(since) {
				olderThanCursor = true
				continue
			}
			collected = append(collected, parsed.Data[i])
		}
		if olderThanCursor || parsed.Page >= parsed.Pages || len(parsed.Data) < linodeAuditPageSize {
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
		entry := mapLinodeAuditEvent(&collected[i])
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

type linodeAuditResponse struct {
	Data    []linodeAuditEvent `json:"data"`
	Page    int                `json:"page"`
	Pages   int                `json:"pages"`
	Results int                `json:"results"`
}

type linodeAuditEvent struct {
	ID       int64  `json:"id"`
	Action   string `json:"action"`
	Created  string `json:"created"`
	Username string `json:"username"`
	Status   string `json:"status"`
	Entity   struct {
		ID    interface{} `json:"id"`
		Label string      `json:"label"`
		Type  string      `json:"type"`
		URL   string      `json:"url"`
	} `json:"entity"`
	SecondaryEntity struct {
		ID    interface{} `json:"id"`
		Label string      `json:"label"`
		Type  string      `json:"type"`
	} `json:"secondary_entity"`
}

func mapLinodeAuditEvent(e *linodeAuditEvent) *access.AuditLogEntry {
	if e == nil || e.ID == 0 {
		return nil
	}
	ts := parseLinodeAuditTime(e.Created)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	outcome := "success"
	switch strings.ToLower(strings.TrimSpace(e.Status)) {
	case "failed":
		outcome = "failure"
	case "scheduled", "started":
		outcome = "pending"
	}
	return &access.AuditLogEntry{
		EventID:          fmt.Sprintf("%d", e.ID),
		EventType:        strings.TrimSpace(e.Action),
		Action:           strings.TrimSpace(e.Action),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.Username),
		TargetExternalID: fmt.Sprintf("%v", e.Entity.ID),
		TargetType:       strings.TrimSpace(e.Entity.Type),
		Outcome:          outcome,
		RawData:          rawMap,
	}
}

func parseLinodeAuditTime(s string) time.Time {
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
	// Linode returns timestamps as "2024-09-01T10:00:00" (no timezone).
	if ts, err := time.Parse("2006-01-02T15:04:05", s); err == nil {
		return ts.UTC()
	}
	return time.Time{}
}

func readLinodeAuditBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, errors.New("linode: empty response")
	}
	defer resp.Body.Close()
	return connutil.ReadBody(resp.Body)
}

var _ access.AccessAuditor = (*LinodeAccessConnector)(nil)
