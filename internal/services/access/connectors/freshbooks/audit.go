package freshbooks

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
	freshbooksAuditPerPage  = 100
	freshbooksAuditMaxPages = 200
)

// FetchAccessAuditLogs streams FreshBooks account-activity entries into
// the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /accounting/account/{account_id}/activities?page=N&per_page=100
//
// Bearer-token auth. Tenants without account-activity entitlement
// return 401 / 403 / 404, soft-skipped via access.ErrAuditNotAvailable.
func (c *FreshBooksAccessConnector) FetchAccessAuditLogs(
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
	base := fmt.Sprintf("%s/accounting/account/%s/activities",
		c.baseURL(), url.PathEscape(strings.TrimSpace(cfg.AccountID)))

	var collected []freshbooksActivity
	for page := 1; page <= freshbooksAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("per_page", fmt.Sprintf("%d", freshbooksAuditPerPage))
		if !since.IsZero() {
			q.Set("updated_min", since.UTC().Format(time.RFC3339))
		}
		fullURL := base + "?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("freshbooks: audit log: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("freshbooks: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope struct {
			Response struct {
				Result struct {
					Activities []freshbooksActivity `json:"activities"`
				} `json:"result"`
			} `json:"response"`
		}
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("freshbooks: decode audit log: %w", err)
		}
		acts := envelope.Response.Result.Activities
		olderThanCursor := false
		for i := range acts {
			ts := parseFreshBooksAuditTime(acts[i].CreatedAt)
			if !since.IsZero() && !ts.IsZero() && !ts.After(since) {
				olderThanCursor = true
				continue
			}
			collected = append(collected, acts[i])
		}
		if olderThanCursor || len(acts) < freshbooksAuditPerPage {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapFreshBooksActivity(&collected[i])
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

type freshbooksActivity struct {
	ID         string `json:"id"`
	Action     string `json:"action"`
	CreatedAt  string `json:"created_at"`
	UserID     string `json:"user_id"`
	Email      string `json:"email"`
	ObjectID   string `json:"object_id"`
	ObjectType string `json:"object_type"`
	Status     string `json:"status"`
}

func mapFreshBooksActivity(e *freshbooksActivity) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseFreshBooksAuditTime(e.CreatedAt)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        strings.TrimSpace(e.Action),
		Action:           strings.TrimSpace(e.Action),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.UserID),
		ActorEmail:       strings.TrimSpace(e.Email),
		TargetExternalID: strings.TrimSpace(e.ObjectID),
		TargetType:       strings.TrimSpace(e.ObjectType),
		Outcome:          strings.TrimSpace(e.Status),
		RawData:          rawMap,
	}
}

func parseFreshBooksAuditTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
