package coupa

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
	coupaAuditPageSize = 100
	coupaAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Coupa audit-trail events into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /api/audit_trails?offset=0&limit=100&updated_after={iso}
//
// The audit-trail API requires the platform "Audit Trails - View" content
// permission; non-eligible API keys surface 401 / 403 / 404 which the
// connector soft-skips via access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *CoupaAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL(cfg) + "/api/audit_trails"

	var collected []coupaAuditEvent
	for page := 0; page < coupaAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("offset", fmt.Sprintf("%d", page*coupaAuditPageSize))
		q.Set("limit", fmt.Sprintf("%d", coupaAuditPageSize))
		if !since.IsZero() {
			q.Set("updated_after", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("coupa: audit_trails: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("coupa: audit_trails: status %d: %s", resp.StatusCode, string(body))
		}
		// Coupa returns either an array directly or an envelope; try both.
		var arr []coupaAuditEvent
		if err := json.Unmarshal(body, &arr); err != nil {
			var envelope coupaAuditPage
			if err := json.Unmarshal(body, &envelope); err != nil {
				return fmt.Errorf("coupa: decode audit_trails: %w", err)
			}
			arr = envelope.AuditTrails
		}
		collected = append(collected, arr...)
		if len(arr) < coupaAuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapCoupaAuditEvent(&collected[i])
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

type coupaAuditEvent struct {
	ID        json.Number `json:"id"`
	EventType string      `json:"event"`
	Action    string      `json:"action"`
	UpdatedAt string      `json:"updated_at"`
	UserID    json.Number `json:"user_id"`
	UserLogin string      `json:"user_login"`
	Subject   string      `json:"subject"`
	IPAddress string      `json:"ip_address"`
}

type coupaAuditPage struct {
	AuditTrails []coupaAuditEvent `json:"audit_trails"`
}

func mapCoupaAuditEvent(e *coupaAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(string(e.ID)) == "" {
		return nil
	}
	ts := parseCoupaTime(e.UpdatedAt)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	action := strings.TrimSpace(e.Action)
	if action == "" {
		action = strings.TrimSpace(e.EventType)
	}
	return &access.AuditLogEntry{
		EventID:          strings.TrimSpace(string(e.ID)),
		EventType:        strings.TrimSpace(e.EventType),
		Action:           action,
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(string(e.UserID)),
		ActorEmail:       strings.TrimSpace(e.UserLogin),
		TargetExternalID: strings.TrimSpace(e.Subject),
		IPAddress:        strings.TrimSpace(e.IPAddress),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseCoupaTime(s string) time.Time {
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

var _ access.AccessAuditor = (*CoupaAccessConnector)(nil)
