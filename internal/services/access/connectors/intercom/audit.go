package intercom

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// FetchAccessAuditLogs streams Intercom admin-activity events into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /admins/activity_logs?created_at_after={unix}&per_page=100
//	    &starting_after={cursor}
//
// Pagination uses Intercom's `pages.next.starting_after` cursor. Tenants
// without an audit-log entitlement (legacy or non-Convert plans) receive
// 401/403/404 which collapses to access.ErrAuditNotAvailable so the
// worker soft-skips the tenant.
func (c *IntercomAccessConnector) FetchAccessAuditLogs(
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
	cursor := since
	startingAfter := ""
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("per_page", "100")
		if !since.IsZero() {
			q.Set("created_at_after", strconv.FormatInt(since.UTC().Unix(), 10))
		}
		if startingAfter != "" {
			q.Set("starting_after", startingAfter)
		}
		fullURL := c.baseURL() + "/admins/activity_logs?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return err
		}
		resp, err := c.doRaw(req)
		if err != nil {
			return err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("intercom: activity_logs: status %d: %s", resp.StatusCode, string(body))
		}
		var page intercomActivityPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("intercom: decode activity page: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Data))
		batchMax := cursor
		for i := range page.Data {
			entry := mapIntercomActivity(&page.Data[i])
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
		next := strings.TrimSpace(page.Pages.Next.StartingAfter)
		if next == "" {
			return nil
		}
		startingAfter = next
	}
}

type intercomActivityPage struct {
	Data  []intercomActivity `json:"data"`
	Pages struct {
		Next struct {
			StartingAfter string `json:"starting_after,omitempty"`
		} `json:"next"`
	} `json:"pages"`
}

type intercomActivity struct {
	ID                  json.Number `json:"id"`
	ActivityType        string      `json:"activity_type"`
	ActivityDescription string      `json:"activity_description,omitempty"`
	CreatedAt           int64       `json:"created_at"`
	Performed           struct {
		ID    json.Number `json:"id"`
		Email string      `json:"email,omitempty"`
		Name  string      `json:"name,omitempty"`
	} `json:"performed_by"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

func mapIntercomActivity(e *intercomActivity) *access.AuditLogEntry {
	if e == nil {
		return nil
	}
	id := strings.TrimSpace(e.ID.String())
	if id == "" || id == "0" {
		return nil
	}
	var ts time.Time
	if e.CreatedAt > 0 {
		ts = time.Unix(e.CreatedAt, 0).UTC()
	}
	rawMap := map[string]interface{}{}
	raw, _ := json.Marshal(e)
	_ = json.Unmarshal(raw, &rawMap)
	actor := strings.TrimSpace(e.Performed.ID.String())
	if actor == "0" {
		actor = ""
	}
	return &access.AuditLogEntry{
		EventID:         id,
		EventType:       strings.TrimSpace(e.ActivityType),
		Action:          strings.TrimSpace(e.ActivityType),
		Timestamp:       ts,
		ActorExternalID: actor,
		ActorEmail:      strings.TrimSpace(e.Performed.Email),
		Outcome:         "success",
		RawData:         rawMap,
	}
}

var _ access.AccessAuditor = (*IntercomAccessConnector)(nil)
