package paychex

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
	paychexAuditLimit    = 100
	paychexAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Paychex worker change-history events into
// the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /companies/{company_id}/workers/changes?limit=100&offset=N&modifiedSince=<RFC3339>
//
// Bearer-token auth (OAuth2 access token). Tenants without the required
// scope return 401 / 403 / 404, soft-skipped via access.ErrAuditNotAvailable.
func (c *PaychexAccessConnector) FetchAccessAuditLogs(
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
	base := fmt.Sprintf("%s/companies/%s/workers/changes",
		c.baseURL(), url.PathEscape(strings.TrimSpace(cfg.CompanyID)))

	var collected []paychexChange
	for page := 0; page < paychexAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", fmt.Sprintf("%d", paychexAuditLimit))
		q.Set("offset", fmt.Sprintf("%d", page*paychexAuditLimit))
		if !since.IsZero() {
			q.Set("modifiedSince", since.UTC().Format(time.RFC3339))
		}
		fullURL := base + "?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("paychex: audit log: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("paychex: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope struct {
			Content []paychexChange `json:"content"`
		}
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("paychex: decode audit log: %w", err)
		}
		olderThanCursor := false
		for i := range envelope.Content {
			ts := parsePaychexAuditTime(envelope.Content[i].EffectiveDate)
			if !since.IsZero() && !ts.IsZero() && !ts.After(since) {
				olderThanCursor = true
				continue
			}
			collected = append(collected, envelope.Content[i])
		}
		if olderThanCursor || len(envelope.Content) < paychexAuditLimit {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapPaychexChange(&collected[i])
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

type paychexChange struct {
	ChangeID      string `json:"changeId"`
	WorkerID      string `json:"workerId"`
	ChangeType    string `json:"changeType"`
	EffectiveDate string `json:"effectiveDate"`
	ChangedBy     string `json:"changedBy"`
	Status        string `json:"status"`
}

func mapPaychexChange(e *paychexChange) *access.AuditLogEntry {
	if e == nil {
		return nil
	}
	id := strings.TrimSpace(e.ChangeID)
	if id == "" {
		return nil
	}
	ts := parsePaychexAuditTime(e.EffectiveDate)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          id,
		EventType:        strings.TrimSpace(e.ChangeType),
		Action:           strings.TrimSpace(e.ChangeType),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.ChangedBy),
		TargetExternalID: strings.TrimSpace(e.WorkerID),
		TargetType:       "worker",
		Outcome:          strings.TrimSpace(e.Status),
		RawData:          rawMap,
	}
}

func parsePaychexAuditTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
