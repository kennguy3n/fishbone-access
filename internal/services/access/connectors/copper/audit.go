package copper

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
	copperAuditPageSize = 100
	copperAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Copper activity events into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /developer_api/v1/activities?page_size=100&page_number=N&minimum_activity_date={epoch}
//
// Activity access requires a developer-key with `Activities:Read` scope;
// missing scope surfaces 401 / 403 / 404 which the connector soft-skips
// via access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *CopperAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL() + "/developer_api/v1/activities"

	var collected []copperActivity
	for page := 1; page <= copperAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page_number", fmt.Sprintf("%d", page))
		q.Set("page_size", fmt.Sprintf("%d", copperAuditPageSize))
		if !since.IsZero() {
			q.Set("minimum_activity_date", fmt.Sprintf("%d", since.UTC().Unix()))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("copper: activities: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("copper: activities: status %d: %s", resp.StatusCode, string(body))
		}
		var activities []copperActivity
		if err := json.Unmarshal(body, &activities); err != nil {
			return fmt.Errorf("copper: decode activities: %w", err)
		}
		collected = append(collected, activities...)
		if len(activities) < copperAuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapCopperActivity(&collected[i])
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

type copperActivity struct {
	ID         int64 `json:"id"`
	ActivityID int64 `json:"activity_id"`
	Type       struct {
		Category string `json:"category"`
		ID       int64  `json:"id"`
	} `json:"type"`
	UserID     int64 `json:"user_id"`
	ActivityAt int64 `json:"activity_date"`
	Parent     struct {
		ID   int64  `json:"id"`
		Type string `json:"type"`
	} `json:"parent"`
	Details string `json:"details"`
}

func mapCopperActivity(a *copperActivity) *access.AuditLogEntry {
	if a == nil {
		return nil
	}
	id := a.ID
	if id == 0 {
		id = a.ActivityID
	}
	if id == 0 {
		return nil
	}
	if a.ActivityAt <= 0 {
		return nil
	}
	ts := time.Unix(a.ActivityAt, 0).UTC()
	raw, _ := json.Marshal(a)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          fmt.Sprintf("%d", id),
		EventType:        strings.TrimSpace(a.Type.Category),
		Action:           strings.TrimSpace(a.Type.Category),
		Timestamp:        ts,
		ActorExternalID:  fmt.Sprintf("%d", a.UserID),
		TargetExternalID: fmt.Sprintf("%d", a.Parent.ID),
		TargetType:       strings.TrimSpace(a.Parent.Type),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

var _ access.AccessAuditor = (*CopperAccessConnector)(nil)
