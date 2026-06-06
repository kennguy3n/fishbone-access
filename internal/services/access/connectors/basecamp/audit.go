package basecamp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// basecampAuditMaxPages bounds the rel="next" Link-header walk over
// /events.json as defense-in-depth, mirroring basecampPeopleMaxPages.
// The walk normally stops when the Link header has no rel="next" or once
// it reaches events older than the cursor.
const basecampAuditMaxPages = 200

// FetchAccessAuditLogs streams Basecamp /events.json entries into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /events.json
//
// Basecamp returns events newest-first and paginates via the RFC 5988
// `Link: rel="next"` header (its documented pagination mechanism), so we
// follow that cursor rather than guessing a page size — the same approach
// SyncIdentities and listBasecampProjectPeople use. Tenants whose OAuth
// token lacks the `events` scope receive 401 / 403, which the connector
// soft-skips via access.ErrAuditNotAvailable.
func (c *BasecampAccessConnector) FetchAccessAuditLogs(
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
	next := c.baseURL(cfg) + "/events.json"

	var collected []basecampAuditEvent
	for page := 0; page < basecampAuditMaxPages && next != ""; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, next)
		if err != nil {
			return err
		}
		status, body, nextLink, err := c.doRawWithLink(req)
		if err != nil {
			return fmt.Errorf("basecamp: audit log: %w", err)
		}
		switch status {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if status < 200 || status >= 300 {
			return fmt.Errorf("basecamp: audit log: status %d: %s", status, string(body))
		}
		var events []basecampAuditEvent
		if err := json.Unmarshal(body, &events); err != nil {
			return fmt.Errorf("basecamp: decode audit log: %w", err)
		}
		olderThanCursor := false
		for i := range events {
			ts := parseBasecampAuditTime(events[i].CreatedAt)
			if ts.IsZero() {
				// Unparseable timestamp: mapBasecampAuditEvent would
				// drop it anyway, so skip it here rather than carrying
				// dead weight in collected.
				continue
			}
			if !since.IsZero() && !ts.After(since) {
				olderThanCursor = true
				continue
			}
			collected = append(collected, events[i])
		}
		// Events are newest-first, so once we cross the cursor there is
		// nothing newer on later pages and we stop. Otherwise advance via
		// the rel="next" Link header until it is absent.
		if olderThanCursor {
			break
		}
		next = nextLink
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapBasecampAuditEvent(&collected[i])
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

type basecampAuditEvent struct {
	ID        int64  `json:"id"`
	Action    string `json:"action"`
	CreatedAt string `json:"created_at"`
	Creator   struct {
		ID    int64  `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email_address"`
	} `json:"creator"`
	Recording struct {
		ID    int64  `json:"id"`
		Type  string `json:"type"`
		Title string `json:"title"`
	} `json:"recording"`
}

func mapBasecampAuditEvent(e *basecampAuditEvent) *access.AuditLogEntry {
	if e == nil || e.ID == 0 {
		return nil
	}
	ts := parseBasecampAuditTime(e.CreatedAt)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          fmt.Sprintf("%d", e.ID),
		EventType:        strings.TrimSpace(e.Action),
		Action:           strings.TrimSpace(e.Action),
		Timestamp:        ts,
		ActorExternalID:  fmt.Sprintf("%d", e.Creator.ID),
		ActorEmail:       strings.TrimSpace(e.Creator.Email),
		TargetExternalID: fmt.Sprintf("%d", e.Recording.ID),
		TargetType:       strings.TrimSpace(e.Recording.Type),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseBasecampAuditTime(s string) time.Time {
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
