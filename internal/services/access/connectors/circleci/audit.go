package circleci

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
	circleAuditPageSize = 100
	circleAuditMaxPages = 200
)

// FetchAccessAuditLogs streams CircleCI organization audit-log
// entries into the access audit pipeline. Implements
// access.AccessAuditor.
//
// Endpoint:
//
//	GET /api/v1.1/audit-logs?offset=N&limit=100&from={iso}
//
// Authentication is the personal API token sent via the
// `Circle-Token` header (same auth as the existing
// /api/v2/me/collaborations probe).
//
// Audit log access is restricted to org admins on the Scale plan;
// other tenants receive 401 / 403 / 404 which the connector soft-skips
// via access.ErrAuditNotAvailable.
//
// To honour the AccessAuditor contract under multi-page sweeps the
// connector buffers every page before advancing the persisted
// cursor: if any page fails the cursor stays where it was, so a
// retry replays the same window rather than silently skipping
// older entries below the persisted cursor.
func (c *CircleCIAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL() + "/api/v1.1/audit-logs"

	var collected []circleAuditEvent
	offset := 0
	for pages := 0; pages < circleAuditMaxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", fmt.Sprintf("%d", circleAuditPageSize))
		q.Set("offset", fmt.Sprintf("%d", offset))
		if !since.IsZero() {
			q.Set("from", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("circleci: audit log: %w", err)
		}
		body, readErr := readCircleAuditBody(resp)
		if readErr != nil {
			return readErr
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("circleci: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var events []circleAuditEvent
		if err := json.Unmarshal(body, &events); err != nil {
			return fmt.Errorf("circleci: decode audit log: %w", err)
		}
		collected = append(collected, events...)
		if len(events) < circleAuditPageSize {
			break
		}
		offset += len(events)
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapCircleAuditEvent(&collected[i])
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

type circleAuditEvent struct {
	ID      string `json:"id"`
	Action  string `json:"action"`
	Schema  string `json:"schema"`
	OccAt   string `json:"occurred_at"`
	Success bool   `json:"success"`
	Actor   struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"actor"`
	Target struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"target"`
	Payload map[string]interface{} `json:"payload"`
}

func mapCircleAuditEvent(e *circleAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseCircleAuditTime(e.OccAt)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	outcome := "success"
	if !e.Success {
		outcome = "failure"
	}
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        strings.TrimSpace(e.Action),
		Action:           strings.TrimSpace(e.Action),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.Actor.ID),
		TargetExternalID: strings.TrimSpace(e.Target.ID),
		TargetType:       strings.TrimSpace(e.Target.Type),
		Outcome:          outcome,
		RawData:          rawMap,
	}
}

func parseCircleAuditTime(s string) time.Time {
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

func readCircleAuditBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, errors.New("circleci: empty response")
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

var _ access.AccessAuditor = (*CircleCIAccessConnector)(nil)
