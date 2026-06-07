package ping_identity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// FetchAccessAuditLogs streams PingOne audit activities into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v1/environments/{envId}/activities?filter=recordedAt gt "{since}"&limit=100&cursor={cursor}
//
// PingOne paginates by an opaque `cursor` returned in the response
// `_links.next.href`. The handler is called once per provider page
// in chronological order so callers can persist `nextSince` (the
// newest recordedAt timestamp) as a monotonic cursor.
//
// Authentication uses an OAuth client-credentials token obtained via
// `fetchAccessToken`. On HTTP 401/403 the connector returns
// access.ErrAuditNotAvailable so callers treat PingOne Free tenants
// (without activity log API access) as plan-gated rather than failing
// the whole sync.
func (c *PingIdentityAccessConnector) FetchAccessAuditLogs(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	sincePartitions map[string]time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	since := sincePartitions[access.DefaultAuditPartition]
	cursor := since
	token, err := c.fetchAccessToken(ctx, cfg, secrets)
	if err != nil {
		if isAuditNotAvailable(err) {
			return access.ErrAuditNotAvailable
		}
		return err
	}
	pageURL := c.apiURL(cfg, fmt.Sprintf("/v1/environments/%s/activities", url.PathEscape(cfg.EnvironmentID)))
	q := url.Values{}
	q.Set("limit", "100")
	if !since.IsZero() {
		q.Set("filter", "recordedAt gt \""+since.UTC().Format(time.RFC3339)+"\"")
	}
	pageURL = pageURL + "?" + q.Encode()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !sameOrigin(c.apiOrigin(cfg), pageURL) {
			return fmt.Errorf("ping_identity: refusing cross-origin pagination URL %q", pageURL)
		}
		req, err := newAuthedRequest(ctx, pageURL, token)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			if isAuditNotAvailable(err) {
				return access.ErrAuditNotAvailable
			}
			return err
		}
		var page pingActivitiesPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("ping_identity: decode activities: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Embedded.Activities))
		batchMax := cursor
		for i := range page.Embedded.Activities {
			entry := mapPingActivity(&page.Embedded.Activities[i])
			if entry == nil {
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
		nextHref := strings.TrimSpace(page.Links.Next.Href)
		if nextHref == "" || len(page.Embedded.Activities) == 0 {
			return nil
		}
		pageURL = nextHref
	}
}

type pingActivitiesPage struct {
	Embedded struct {
		Activities []pingActivity `json:"activities"`
	} `json:"_embedded"`
	Links struct {
		Next struct {
			Href string `json:"href"`
		} `json:"next"`
	} `json:"_links"`
}

type pingActivity struct {
	ID         string `json:"id"`
	RecordedAt string `json:"recordedAt"`
	Action     struct {
		Type   string `json:"type"`
		Result struct {
			Status string `json:"status"`
		} `json:"result"`
	} `json:"action"`
	Actors struct {
		User struct {
			ID       string `json:"id"`
			Username string `json:"username"`
		} `json:"user"`
		Client struct {
			IP        string `json:"ip"`
			UserAgent string `json:"user_agent"`
		} `json:"client"`
	} `json:"actors"`
	Resources []struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"resources"`
}

func mapPingActivity(a *pingActivity) *access.AuditLogEntry {
	if a == nil || strings.TrimSpace(a.RecordedAt) == "" {
		return nil
	}
	ts, _ := time.Parse(time.RFC3339Nano, a.RecordedAt)
	if ts.IsZero() {
		ts, _ = time.Parse(time.RFC3339, a.RecordedAt)
	}
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(a)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	eventType := strings.TrimSpace(a.Action.Type)
	if eventType == "" {
		eventType = "activity"
	}
	outcome := "success"
	if !strings.EqualFold(strings.TrimSpace(a.Action.Result.Status), "success") && strings.TrimSpace(a.Action.Result.Status) != "" {
		outcome = "failure"
	}
	target := ""
	targetType := ""
	if len(a.Resources) > 0 {
		target = a.Resources[0].ID
		targetType = a.Resources[0].Type
	}
	return &access.AuditLogEntry{
		EventID:          strings.TrimSpace(a.ID),
		EventType:        eventType,
		Action:           eventType,
		Timestamp:        ts,
		ActorExternalID:  a.Actors.User.ID,
		ActorEmail:       a.Actors.User.Username,
		TargetExternalID: target,
		TargetType:       targetType,
		IPAddress:        a.Actors.Client.IP,
		UserAgent:        a.Actors.Client.UserAgent,
		Outcome:          outcome,
		RawData:          rawMap,
	}
}

func isAuditNotAvailable(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "status 401") || strings.Contains(msg, "status 403")
}

var _ access.AccessAuditor = (*PingIdentityAccessConnector)(nil)
