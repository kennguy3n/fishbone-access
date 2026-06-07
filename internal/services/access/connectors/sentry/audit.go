package sentry

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

// FetchAccessAuditLogs streams Sentry audit log events into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /api/0/organizations/{slug}/audit-logs/?cursor={cursor}
//
// Sentry paginates via RFC 5988 `Link: rel="next"; results="true"`
// headers; the handler is called once per page in chronological order.
// When `since` is non-zero we client-side filter events so older
// records the API still returns are dropped (Sentry's audit log
// endpoint does not expose a `?since=` filter).
func (c *SentryAccessConnector) FetchAccessAuditLogs(
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

	startQuery := url.Values{}
	startQuery.Set("per_page", "100")
	nextURL := c.baseURL() + "/api/0/organizations/" + url.PathEscape(cfg.OrganizationSlug) + "/audit-logs/?" + startQuery.Encode()
	for nextURL != "" {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.assertSameHost(nextURL); err != nil {
			return err
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, nextURL)
		if err != nil {
			return err
		}
		resp, err := c.doRaw(req)
		if err != nil {
			if resp != nil {
				switch resp.StatusCode {
				case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
					return access.ErrAuditNotAvailable
				}
			}
			return err
		}
		var page sentryAuditPage
		if err := json.Unmarshal(resp.Body, &page); err != nil {
			return fmt.Errorf("sentry: decode audit log page: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Rows))
		batchMax := cursor
		for i := range page.Rows {
			entry := mapSentryAuditLog(&page.Rows[i])
			if entry == nil {
				continue
			}
			if !since.IsZero() && !entry.Timestamp.After(since) {
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
		next := parseSentryNext(resp.Header.Get("Link"))
		if next == "" {
			return nil
		}
		if c.urlOverride != "" {
			next = strings.Replace(next, defaultBaseURL, strings.TrimRight(c.urlOverride, "/"), 1)
		}
		nextURL = next
	}
	return nil
}

type sentryAuditPage struct {
	Rows    []sentryAuditLog `json:"rows"`
	Options struct {
		Cursor string `json:"cursor"`
	} `json:"options"`
}

type sentryAuditLog struct {
	ID          string `json:"id"`
	Event       string `json:"event"`
	Note        string `json:"note"`
	IP          string `json:"ipAddress"`
	DateCreated string `json:"dateCreated"`
	Actor       struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name"`
	} `json:"actor"`
	TargetUser struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"targetUser"`
	TargetObject string `json:"targetObject"`
}

func mapSentryAuditLog(e *sentryAuditLog) *access.AuditLogEntry {
	if e == nil || e.ID == "" {
		return nil
	}
	ts, _ := time.Parse(time.RFC3339Nano, e.DateCreated)
	if ts.IsZero() {
		ts, _ = time.Parse(time.RFC3339, e.DateCreated)
	}
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        e.Event,
		Action:           e.Event,
		Timestamp:        ts,
		ActorExternalID:  e.Actor.ID,
		ActorEmail:       e.Actor.Email,
		TargetExternalID: e.TargetUser.ID,
		IPAddress:        e.IP,
		Outcome:          "success",
		RawData:          rawMap,
	}
}

var _ access.AccessAuditor = (*SentryAccessConnector)(nil)
