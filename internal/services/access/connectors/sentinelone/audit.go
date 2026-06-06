package sentinelone

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"context"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// FetchAccessAuditLogs streams SentinelOne activity events into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /web/api/v2.1/activities?createdAt__gte={since}&limit=100&cursor={cursor}
//
// SentinelOne paginates by an opaque `nextCursor` returned in the
// `pagination` envelope. The handler is called once per provider
// page in chronological order so callers can persist `nextSince`
// (the newest createdAt timestamp seen so far) as a monotonic cursor.
//
// Authentication is `Authorization: ApiToken {token}`. On HTTP 401/403
// the connector returns access.ErrAuditNotAvailable so callers treat
// the tenant as plan-gated rather than failing the whole sync.
func (c *SentinelOneAccessConnector) FetchAccessAuditLogs(
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
	cursor := since
	pageCursor := ""
	base := c.baseURL(cfg)
	for pageNum := 0; pageNum < auditMaxPages; pageNum++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", "100")
		if !since.IsZero() {
			q.Set("createdAt__gte", since.UTC().Format(time.RFC3339))
		}
		if pageCursor != "" {
			q.Set("cursor", pageCursor)
		}
		full := base + "/web/api/v2.1/activities?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, full)
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
		var page sentineloneActivitiesResponse
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("sentinelone: decode activities: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Data))
		batchMax := cursor
		for i := range page.Data {
			entry := mapSentineloneActivity(&page.Data[i])
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
		if page.Pagination.NextCursor == nil || strings.TrimSpace(*page.Pagination.NextCursor) == "" {
			return nil
		}
		pageCursor = *page.Pagination.NextCursor
	}
	// Page budget exhausted while the API still reports more pages; stop
	// rather than loop unbounded. The persisted cursor lets the next run
	// resume where this one left off.
	return nil
}

type sentineloneActivitiesResponse struct {
	Data       []sentineloneActivity `json:"data"`
	Pagination struct {
		NextCursor *string `json:"nextCursor"`
		TotalItems int     `json:"totalItems"`
	} `json:"pagination"`
}

type sentineloneActivity struct {
	ID                   string `json:"id"`
	ActivityType         int    `json:"activityType"`
	ActivityTypeName     string `json:"activityTypeName"`
	PrimaryDescription   string `json:"primaryDescription"`
	SecondaryDescription string `json:"secondaryDescription"`
	CreatedAt            string `json:"createdAt"`
	UserEmail            string `json:"userEmail"`
	UserID               string `json:"userId"`
	AgentID              string `json:"agentId"`
}

func mapSentineloneActivity(a *sentineloneActivity) *access.AuditLogEntry {
	if a == nil || strings.TrimSpace(a.CreatedAt) == "" {
		return nil
	}
	ts, _ := time.Parse(time.RFC3339Nano, a.CreatedAt)
	if ts.IsZero() {
		ts, _ = time.Parse(time.RFC3339, a.CreatedAt)
	}
	if ts.IsZero() {
		return nil
	}
	eventType := strings.TrimSpace(a.ActivityTypeName)
	if eventType == "" {
		eventType = fmt.Sprintf("activity_type_%d", a.ActivityType)
	}
	raw, _ := json.Marshal(a)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          strings.TrimSpace(a.ID),
		EventType:        eventType,
		Action:           eventType,
		Timestamp:        ts,
		ActorExternalID:  a.UserID,
		ActorEmail:       a.UserEmail,
		TargetExternalID: a.AgentID,
		Outcome:          "success",
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

var _ access.AccessAuditor = (*SentinelOneAccessConnector)(nil)
