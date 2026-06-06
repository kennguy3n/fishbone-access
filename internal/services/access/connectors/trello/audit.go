package trello

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

const (
	trelloAuditPageSize = 50
	// trelloAuditMaxPages bounds a single sweep to ~10k events. The
	// `since` cursor narrows the window between runs so this only
	// kicks in on the very first sync of a long-dormant workspace.
	trelloAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Trello organization-action events into
// the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /1/organizations/{id}/actions?since={ts}&before={id}&limit=50
//
// Trello surfaces audit-style events through the generic /actions feed.
// The endpoint paginates reverse-chronologically with a `before={id}`
// cursor: page 1 is the newest 50 events, page 2 is the next-newest
// 50, and so on. The AccessAuditor contract requires that any
// `nextSince` passed to the handler cover only events already yielded
// to the handler — the worker persists this cursor even on partial
// failure (see internal/workers/handlers/access_audit.go:124-132).
//
// To honour the contract under reverse-chronological pagination we
// collect the full sweep first, then reverse the entire collection
// into chronological (oldest-first) order, then call the handler once
// with the maximum timestamp as `nextSince`. If the handler call
// fails the cursor is never advanced past un-yielded events, so a
// retry replays the same window rather than silently skipping older
// events that the worker had already persisted past.
//
// Tenants whose token is not a Workspace admin receive 401/403, which
// collapses to access.ErrAuditNotAvailable so the worker soft-skips
// the tenant rather than looping.
func (c *TrelloAccessConnector) FetchAccessAuditLogs(
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

	var collected []trelloAction
	before := ""
	for page := 0; page < trelloAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", strconv.Itoa(trelloAuditPageSize))
		if !since.IsZero() {
			q.Set("since", since.UTC().Format(time.RFC3339))
		}
		if before != "" {
			q.Set("before", before)
		}
		path := "/organizations/" + url.PathEscape(cfg.OrganizationID) + "/actions"
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path, q)
		if err != nil {
			return err
		}
		resp, err := c.doRaw(req)
		if err != nil {
			return err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("trello: actions: status %d: %s", resp.StatusCode, string(body))
		}
		var actions []trelloAction
		if err := json.Unmarshal(body, &actions); err != nil {
			return fmt.Errorf("trello: decode actions: %w", err)
		}
		if len(actions) == 0 {
			break
		}
		collected = append(collected, actions...)
		if len(actions) < trelloAuditPageSize {
			break
		}
		// `actions[len-1]` is the oldest action on this page; the
		// next call walks further back in time by using it as the
		// `before` cursor.
		before = actions[len(actions)-1].ID
	}

	if len(collected) == 0 {
		return nil
	}

	// Walk the collected pages oldest-first so the handler sees a
	// chronologically ascending batch and `nextSince` covers every
	// event we just yielded.
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := len(collected) - 1; i >= 0; i-- {
		entry := mapTrelloAction(&collected[i])
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

type trelloAction struct {
	ID              string                 `json:"id"`
	Type            string                 `json:"type"`
	Date            string                 `json:"date"`
	IDMemberCreator string                 `json:"idMemberCreator"`
	MemberCreator   trelloAuditMember      `json:"memberCreator"`
	Data            map[string]interface{} `json:"data,omitempty"`
}

type trelloAuditMember struct {
	ID       string `json:"id,omitempty"`
	Username string `json:"username,omitempty"`
	FullName string `json:"fullName,omitempty"`
}

func mapTrelloAction(a *trelloAction) *access.AuditLogEntry {
	if a == nil || strings.TrimSpace(a.ID) == "" {
		return nil
	}
	ts := parseTrelloTime(a.Date)
	var targetID, targetType string
	if a.Data != nil {
		if card, ok := a.Data["card"].(map[string]interface{}); ok {
			if id, ok := card["id"].(string); ok && id != "" {
				targetID = id
				targetType = "card"
			}
		}
		if targetID == "" {
			if board, ok := a.Data["board"].(map[string]interface{}); ok {
				if id, ok := board["id"].(string); ok && id != "" {
					targetID = id
					targetType = "board"
				}
			}
		}
		if targetID == "" {
			if mem, ok := a.Data["member"].(map[string]interface{}); ok {
				if id, ok := mem["id"].(string); ok && id != "" {
					targetID = id
					targetType = "member"
				}
			}
		}
	}
	rawMap := map[string]interface{}{}
	raw, _ := json.Marshal(a)
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          a.ID,
		EventType:        strings.TrimSpace(a.Type),
		Action:           strings.TrimSpace(a.Type),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(a.IDMemberCreator),
		TargetExternalID: targetID,
		TargetType:       targetType,
		Outcome:          "success",
		RawData:          rawMap,
	}
}

// parseTrelloTime parses Trello's action.date timestamps. Trello emits
// RFC3339 with millisecond precision; older payloads omit fractions.
func parseTrelloTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if ts, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return ts
	}
	if ts, err := time.Parse(time.RFC3339, s); err == nil {
		return ts
	}
	return time.Time{}
}

var _ access.AccessAuditor = (*TrelloAccessConnector)(nil)
