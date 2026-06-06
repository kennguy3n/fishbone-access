package activecampaign

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
	activecampaignAuditPageSize = 100
	activecampaignAuditMaxPages = 200
)

// FetchAccessAuditLogs streams ActiveCampaign activity events into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /api/3/activities?limit=100&offset=N&filters[gt][tstamp]={iso}
//
// Activity access requires an admin-tier API token; non-admin tokens
// receive 401 / 403 / 404 which the connector soft-skips via
// access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *ActiveCampaignAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL(cfg) + "/api/3/activities"

	var collected []activecampaignActivity
	offset := 0
	for page := 0; page < activecampaignAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", fmt.Sprintf("%d", activecampaignAuditPageSize))
		q.Set("offset", fmt.Sprintf("%d", offset))
		if !since.IsZero() {
			q.Set("filters[gt][tstamp]", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("activecampaign: activities: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("activecampaign: activities: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope activecampaignActivityPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("activecampaign: decode activities: %w", err)
		}
		collected = append(collected, envelope.Activities...)
		if len(envelope.Activities) < activecampaignAuditPageSize {
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
		entry := mapActiveCampaignActivity(&collected[i])
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

type activecampaignActivity struct {
	ID        string `json:"id"`
	Type      string `json:"reltype"`
	Action    string `json:"action"`
	UserID    string `json:"user"`
	ContactID string `json:"contact"`
	Timestamp string `json:"tstamp"`
	Reference string `json:"reference"`
	IPAddress string `json:"ipaddress"`
}

type activecampaignActivityPage struct {
	Activities []activecampaignActivity `json:"activities"`
	Meta       struct {
		Total string `json:"total"`
	} `json:"meta"`
}

func mapActiveCampaignActivity(a *activecampaignActivity) *access.AuditLogEntry {
	if a == nil || strings.TrimSpace(a.ID) == "" {
		return nil
	}
	ts := parseActiveCampaignTime(a.Timestamp)
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
		EventID:          strings.TrimSpace(a.ID),
		EventType:        strings.TrimSpace(a.Type),
		Action:           action,
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(a.UserID),
		TargetExternalID: strings.TrimSpace(a.ContactID),
		IPAddress:        strings.TrimSpace(a.IPAddress),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseActiveCampaignTime(s string) time.Time {
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
	if ts, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
		return ts.UTC()
	}
	return time.Time{}
}

var _ access.AccessAuditor = (*ActiveCampaignAccessConnector)(nil)
