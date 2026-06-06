package clio

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
	clioAuditPageSize = 100
	clioAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Clio activity events into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /api/v4/activities?page=1&per_page=100&since={iso}
//
// The activities API requires the OAuth2 `activities:read` scope; tokens
// without it surface 401 / 403 / 404, which the connector soft-skips via
// access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *ClioAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL() + "/api/v4/activities"

	var collected []clioActivity
	for page := 1; page <= clioAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("per_page", fmt.Sprintf("%d", clioAuditPageSize))
		if !since.IsZero() {
			q.Set("since", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("clio: activities: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("clio: activities: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope clioActivityPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("clio: decode activities: %w", err)
		}
		collected = append(collected, envelope.Data...)
		if len(envelope.Data) < clioAuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapClioActivity(&collected[i])
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

type clioActivity struct {
	ID        json.Number `json:"id"`
	Type      string      `json:"type"`
	Date      string      `json:"date"`
	UserID    json.Number `json:"user_id"`
	UserEmail string      `json:"user_email"`
	MatterID  json.Number `json:"matter_id"`
	IPAddress string      `json:"ip_address"`
	Action    string      `json:"action"`
}

type clioActivityPage struct {
	Data []clioActivity `json:"data"`
	Meta struct {
		Paging struct {
			Next     string `json:"next"`
			Previous string `json:"previous"`
		} `json:"paging"`
	} `json:"meta"`
}

func mapClioActivity(a *clioActivity) *access.AuditLogEntry {
	if a == nil || strings.TrimSpace(string(a.ID)) == "" {
		return nil
	}
	ts := parseClioTime(a.Date)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(a)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	action := strings.TrimSpace(a.Action)
	if action == "" {
		action = strings.TrimSpace(a.Type)
	}
	return &access.AuditLogEntry{
		EventID:          strings.TrimSpace(string(a.ID)),
		EventType:        strings.TrimSpace(a.Type),
		Action:           action,
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(string(a.UserID)),
		ActorEmail:       strings.TrimSpace(a.UserEmail),
		TargetExternalID: strings.TrimSpace(string(a.MatterID)),
		IPAddress:        strings.TrimSpace(a.IPAddress),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseClioTime(s string) time.Time {
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

var _ access.AccessAuditor = (*ClioAccessConnector)(nil)
