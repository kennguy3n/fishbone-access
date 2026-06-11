package vercel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	vercelAuditPageSize = 100
	vercelAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Vercel team "audit log" events into
// the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v1/teams/{team_id}/audit-logs?limit=100&since={iso}
//	GET /v2/events?teamId={team_id}&limit=100&since={iso}   (legacy fallback)
//
// Vercel audit log access is a Pro / Enterprise feature; the
// connector soft-skips tenants without access (401 / 403 / 404 →
// access.ErrAuditNotAvailable). The endpoint also requires
// `team_id` in config — when blank we return ErrAuditNotAvailable
// because audit logs are scoped to a team, not a personal account.
//
// Pagination uses the Vercel `pagination.next` opaque cursor. The
// connector buffers all pages before invoking the handler so a
// partial sweep does not advance the persisted cursor.
func (c *VercelAccessConnector) FetchAccessAuditLogs(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	sincePartitions map[string]time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	if strings.TrimSpace(cfg.TeamID) == "" {
		return access.ErrAuditNotAvailable
	}
	since := sincePartitions[access.DefaultAuditPartition]
	base := "/v1/teams/" + url.PathEscape(cfg.TeamID) + "/audit-logs"

	var collected []vercelAuditEvent
	until := ""
	for pages := 0; pages < vercelAuditMaxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", fmt.Sprintf("%d", vercelAuditPageSize))
		if !since.IsZero() {
			q.Set("since", since.UTC().Format(time.RFC3339))
		}
		if until != "" {
			q.Set("until", until)
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("vercel: audit log: %w", err)
		}
		body, readErr := readVercelAuditBody(resp)
		if readErr != nil {
			return readErr
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusPaymentRequired:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("vercel: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var parsed vercelAuditResponse
		if err := json.Unmarshal(body, &parsed); err != nil {
			return fmt.Errorf("vercel: decode audit log: %w", err)
		}
		events := parsed.Events
		if len(events) == 0 && len(parsed.AuditLogs) > 0 {
			events = parsed.AuditLogs
		}
		collected = append(collected, events...)
		next := parsed.Pagination.Next
		if next == "" {
			break
		}
		until = next
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapVercelAuditEvent(&collected[i])
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

type vercelAuditResponse struct {
	Events     []vercelAuditEvent `json:"events"`
	AuditLogs  []vercelAuditEvent `json:"auditLogs"`
	Pagination struct {
		Next string `json:"next,omitempty"`
	} `json:"pagination"`
}

type vercelAuditEvent struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Action    string `json:"action"`
	CreatedAt int64  `json:"createdAt"`
	Principal struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"principal"`
	Entity struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"entity"`
	Outcome string                 `json:"outcome,omitempty"`
	Payload map[string]interface{} `json:"payload,omitempty"`
}

func mapVercelAuditEvent(e *vercelAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := vercelEpochMs(e.CreatedAt)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	action := strings.TrimSpace(e.Action)
	if action == "" {
		action = strings.TrimSpace(e.Type)
	}
	outcome := strings.TrimSpace(e.Outcome)
	if outcome == "" {
		outcome = "success"
	}
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        strings.TrimSpace(e.Type),
		Action:           action,
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.Principal.ID),
		ActorEmail:       strings.TrimSpace(e.Principal.Email),
		TargetExternalID: strings.TrimSpace(e.Entity.ID),
		TargetType:       strings.TrimSpace(e.Entity.Type),
		Outcome:          outcome,
		RawData:          rawMap,
	}
}

func vercelEpochMs(ms int64) time.Time {
	if ms <= 0 {
		return time.Time{}
	}
	return time.Unix(0, ms*int64(time.Millisecond)).UTC()
}

func readVercelAuditBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, errors.New("vercel: empty response")
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

var _ access.AccessAuditor = (*VercelAccessConnector)(nil)
