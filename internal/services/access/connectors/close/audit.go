package close

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
	closeAuditPageSize = 100
	closeAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Close activity events into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /api/v1/activity?_limit=100&_skip=N&date_created__gt={iso}
//
// Activity access requires an admin or super-user API key; lower-tier
// keys surface 401 / 403 / 404 which the connector soft-skips via
// access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *CloseAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL() + "/api/v1/activity"

	var collected []closeActivity
	skip := 0
	for page := 0; page < closeAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("_limit", fmt.Sprintf("%d", closeAuditPageSize))
		q.Set("_skip", fmt.Sprintf("%d", skip))
		if !since.IsZero() {
			q.Set("date_created__gt", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("close: activity: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("close: activity: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope closeActivityPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("close: decode activity: %w", err)
		}
		collected = append(collected, envelope.Data...)
		if !envelope.HasMore || len(envelope.Data) == 0 {
			break
		}
		skip += len(envelope.Data)
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapCloseActivity(&collected[i])
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

type closeActivity struct {
	ID          string `json:"id"`
	Type        string `json:"_type"`
	UserID      string `json:"user_id"`
	UserName    string `json:"user_name"`
	LeadID      string `json:"lead_id"`
	DateCreated string `json:"date_created"`
	DateUpdated string `json:"date_updated"`
}

type closeActivityPage struct {
	HasMore bool            `json:"has_more"`
	Data    []closeActivity `json:"data"`
}

func mapCloseActivity(a *closeActivity) *access.AuditLogEntry {
	if a == nil || strings.TrimSpace(a.ID) == "" {
		return nil
	}
	tsRaw := a.DateUpdated
	if strings.TrimSpace(tsRaw) == "" {
		tsRaw = a.DateCreated
	}
	ts := parseCloseTime(tsRaw)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(a)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          strings.TrimSpace(a.ID),
		EventType:        strings.TrimSpace(a.Type),
		Action:           strings.TrimSpace(a.Type),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(a.UserID),
		ActorEmail:       strings.TrimSpace(a.UserName),
		TargetExternalID: strings.TrimSpace(a.LeadID),
		TargetType:       "lead",
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseCloseTime(s string) time.Time {
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

var _ access.AccessAuditor = (*CloseAccessConnector)(nil)
