package constant_contact

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
	constantContactAuditPageSize = 100
	constantContactAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Constant Contact account-activity events
// into the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v3/account/activity?limit=100&offset=N&created_after={iso}
//
// Activity-log access requires an admin-tier OAuth scope; lower-tier
// tokens surface 401 / 403 / 404 which the connector soft-skips via
// access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *ConstantContactAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL() + "/v3/account/activity"

	var collected []constantContactActivity
	offset := 0
	for page := 0; page < constantContactAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", fmt.Sprintf("%d", constantContactAuditPageSize))
		q.Set("offset", fmt.Sprintf("%d", offset))
		if !since.IsZero() {
			q.Set("created_after", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("constant_contact: account-activity: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("constant_contact: account-activity: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope constantContactActivityPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("constant_contact: decode account-activity: %w", err)
		}
		collected = append(collected, envelope.Activities...)
		if len(envelope.Activities) < constantContactAuditPageSize {
			break
		}
		offset += len(envelope.Activities)
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapConstantContactActivity(&collected[i])
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

type constantContactActivity struct {
	ActivityID  string `json:"activity_id"`
	ActivityKey string `json:"activity_key"`
	Action      string `json:"action"`
	UserEmail   string `json:"user_email"`
	UserID      string `json:"user_id"`
	CreatedAt   string `json:"created_at"`
	TargetID    string `json:"target_id"`
	TargetType  string `json:"target_type"`
}

type constantContactActivityPage struct {
	Activities []constantContactActivity `json:"activities"`
	Links      struct {
		Next struct {
			Href string `json:"href"`
		} `json:"next"`
	} `json:"_links"`
}

func mapConstantContactActivity(a *constantContactActivity) *access.AuditLogEntry {
	if a == nil || strings.TrimSpace(a.ActivityID) == "" {
		return nil
	}
	ts := parseConstantContactTime(a.CreatedAt)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(a)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	action := strings.TrimSpace(a.Action)
	if action == "" {
		action = strings.TrimSpace(a.ActivityKey)
	}
	return &access.AuditLogEntry{
		EventID:          strings.TrimSpace(a.ActivityID),
		EventType:        strings.TrimSpace(a.ActivityKey),
		Action:           action,
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(a.UserID),
		ActorEmail:       strings.TrimSpace(a.UserEmail),
		TargetExternalID: strings.TrimSpace(a.TargetID),
		TargetType:       strings.TrimSpace(a.TargetType),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseConstantContactTime(s string) time.Time {
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

var _ access.AccessAuditor = (*ConstantContactAccessConnector)(nil)
