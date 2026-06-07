package namely

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
	namelyAuditPerPage  = 100
	namelyAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Namely profile-change events into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET https://{subdomain}.namely.com/api/v1/reports/changes?page=N&per_page=100
//
// Bearer-token auth. Tenants without the report-change entitlement
// return 401 / 403 / 404, soft-skipped via access.ErrAuditNotAvailable.
func (c *NamelyAccessConnector) FetchAccessAuditLogs(
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

	var collected []namelyAuditEvent
	for page := 1; page <= namelyAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("per_page", fmt.Sprintf("%d", namelyAuditPerPage))
		if !since.IsZero() {
			q.Set("changed_since", since.UTC().Format(time.RFC3339))
		}
		fullURL := c.baseURL(cfg) + "/api/v1/reports/changes?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("namely: audit log: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("namely: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope struct {
			Reports []namelyAuditEvent `json:"reports"`
		}
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("namely: decode audit log: %w", err)
		}
		olderThanCursor := false
		for i := range envelope.Reports {
			ts := parseNamelyAuditTime(envelope.Reports[i].ChangedAt)
			if !since.IsZero() && !ts.IsZero() && !ts.After(since) {
				olderThanCursor = true
				continue
			}
			collected = append(collected, envelope.Reports[i])
		}
		if olderThanCursor || len(envelope.Reports) < namelyAuditPerPage {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapNamelyAuditEvent(&collected[i])
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

type namelyAuditEvent struct {
	ID        string `json:"id"`
	Action    string `json:"action"`
	ChangedAt string `json:"changed_at"`
	ChangedBy string `json:"changed_by"`
	ProfileID string `json:"profile_id"`
	FieldName string `json:"field_name"`
	Status    string `json:"status"`
	ChangedIP string `json:"changed_ip"`
	ChangerEM string `json:"changer_email"`
}

func mapNamelyAuditEvent(e *namelyAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseNamelyAuditTime(e.ChangedAt)
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
		ActorExternalID:  strings.TrimSpace(e.ChangedBy),
		ActorEmail:       strings.TrimSpace(e.ChangerEM),
		TargetExternalID: strings.TrimSpace(e.ProfileID),
		TargetType:       "profile",
		IPAddress:        strings.TrimSpace(e.ChangedIP),
		Outcome:          strings.TrimSpace(e.Status),
		RawData:          rawMap,
	}
}

func parseNamelyAuditTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
