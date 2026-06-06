package wordpress

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	wpAuditPageSize = 100
	wpAuditMaxPages = 200
)

// FetchAccessAuditLogs streams WordPress.com Activity Log entries
// into the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /rest/v1.1/sites/{site}/activity?number=100&page=N&after={iso}
//
// The Activity Log is only available on WordPress.com hosted sites;
// self-hosted installations return 401/403/404 on this path, which the
// connector soft-skips via access.ErrAuditNotAvailable per
// docs/architecture.md §2.
func (c *WordPressAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL() + "/rest/v1.1/sites/" + url.PathEscape(cfg.Site) + "/activity"

	var collected []wpActivityEntry
	for page := 1; page <= wpAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("number", fmt.Sprintf("%d", wpAuditPageSize))
		q.Set("page", fmt.Sprintf("%d", page))
		if !since.IsZero() {
			q.Set("after", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("wordpress: audit: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("wordpress: audit: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope wpActivityPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("wordpress: decode audit: %w", err)
		}
		collected = append(collected, envelope.Current.Ordereditems...)
		if len(envelope.Current.Ordereditems) < wpAuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapWordPressActivity(&collected[i])
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

type wpActivityActor struct {
	Type       string `json:"type"`
	Name       string `json:"name"`
	Login      string `json:"wpcom_login"`
	WPCOMUser  string `json:"wpcom_user_id"`
	Email      string `json:"email"`
	ExternalID string `json:"external_user_id"`
}

type wpActivityObject struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	ObjectID string `json:"object_id"`
}

type wpActivityEntry struct {
	ActivityID  string           `json:"activity_id"`
	Name        string           `json:"name"`
	Gridicon    string           `json:"gridicon"`
	Status      string           `json:"status"`
	PublishedAt string           `json:"published"`
	Actor       wpActivityActor  `json:"actor"`
	Object      wpActivityObject `json:"object"`
}

type wpActivityPage struct {
	Current struct {
		Ordereditems []wpActivityEntry `json:"orderedItems"`
	} `json:"current"`
}

func mapWordPressActivity(e *wpActivityEntry) *access.AuditLogEntry {
	if e == nil {
		return nil
	}
	ts, err := time.Parse(time.RFC3339, strings.TrimSpace(e.PublishedAt))
	if err != nil {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	actorID := strings.TrimSpace(e.Actor.WPCOMUser)
	if actorID == "" {
		actorID = strings.TrimSpace(e.Actor.ExternalID)
	}
	outcome := strings.ToLower(strings.TrimSpace(e.Status))
	if outcome == "" {
		outcome = "success"
	}
	return &access.AuditLogEntry{
		EventID:          strings.TrimSpace(e.ActivityID),
		EventType:        strings.TrimSpace(e.Name),
		Action:           strings.TrimSpace(e.Name),
		Timestamp:        ts.UTC(),
		ActorExternalID:  actorID,
		ActorEmail:       strings.TrimSpace(e.Actor.Email),
		TargetExternalID: strings.TrimSpace(e.Object.ObjectID),
		TargetType:       strings.TrimSpace(e.Object.Type),
		Outcome:          outcome,
		RawData:          rawMap,
	}
}

var _ access.AccessAuditor = (*WordPressAccessConnector)(nil)
