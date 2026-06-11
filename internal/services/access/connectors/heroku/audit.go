package heroku

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

// FetchAccessAuditLogs streams Heroku Enterprise audit-trail entries
// into the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /enterprise-accounts/{enterprise}/events?since={iso}
//
// Enterprise audit access is gated behind the Heroku Enterprise tier
// and requires an admin API key. Non-Enterprise / non-admin tenants
// return 401 / 403 / 404 / 422 which the connector soft-skips via
// access.ErrAuditNotAvailable.
//
// Heroku paginates list endpoints with the Range/Next-Range header
// mechanism, so a busy enterprise's audit window spans many pages. The
// connector follows every page (via doPaged) and buffers the full window
// before advancing `nextSince`, so neither a mid-stream request failure nor
// a window larger than a single page can drop audit events or corrupt the
// persisted cursor.
func (c *HerokuAccessConnector) FetchAccessAuditLogs(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	sincePartitions map[string]time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	enterprise := strings.TrimSpace(cfg.TeamName)
	if enterprise == "" {
		return access.ErrAuditNotAvailable
	}
	since := sincePartitions[access.DefaultAuditPartition]
	path := "/enterprise-accounts/" + url.PathEscape(enterprise) + "/events"
	if !since.IsZero() {
		path = path + "?since=" + since.UTC().Format(time.RFC3339)
	}
	var events []herokuAuditEvent
	status, err := c.doPaged(ctx, secrets, auditTrailAccept, path, func(body []byte) error {
		var page []herokuAuditEvent
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("heroku: decode audit trail: %w", err)
		}
		events = append(events, page...)
		return nil
	})
	// Permission/tier gating is reported on the first page; map it to a
	// soft skip before surfacing any generic transport error.
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusUnprocessableEntity:
		return access.ErrAuditNotAvailable
	}
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(events))
	batchMax := since
	for i := range events {
		entry := mapHerokuAuditEvent(&events[i])
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

type herokuAuditEvent struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Action    string `json:"action"`
	CreatedAt string `json:"created_at"`
	Actor     struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"actor"`
	App  *herokuAuditApp  `json:"app,omitempty"`
	Data *json.RawMessage `json:"data,omitempty"`
}

type herokuAuditApp struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func mapHerokuAuditEvent(e *herokuAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseHerokuAuditTime(e.CreatedAt)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	target := ""
	targetType := ""
	if e.App != nil {
		target = strings.TrimSpace(e.App.ID)
		targetType = "app"
		if target == "" {
			target = strings.TrimSpace(e.App.Name)
		}
	}
	action := strings.TrimSpace(e.Action)
	if action == "" {
		action = strings.TrimSpace(e.Type)
	}
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        strings.TrimSpace(e.Type),
		Action:           action,
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.Actor.ID),
		ActorEmail:       strings.TrimSpace(e.Actor.Email),
		TargetExternalID: target,
		TargetType:       targetType,
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseHerokuAuditTime(s string) time.Time {
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

var _ access.AccessAuditor = (*HerokuAccessConnector)(nil)
