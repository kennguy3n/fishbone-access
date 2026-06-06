package apollo

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
	apolloAuditPageSize = 100
	apolloAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Apollo.io activity events into the access
// audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v1/activities?per_page=100&page=N&updated_at_gt={iso}
//
// Activity API access requires team-admin scope; lower scopes return
// 401 / 403 / 404 which the connector soft-skips via
// access.ErrAuditNotAvailable per docs/architecture.md §2.
func (c *ApolloAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL() + "/v1/activities"

	var collected []apolloActivity
	for page := 1; page <= apolloAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("per_page", fmt.Sprintf("%d", apolloAuditPageSize))
		if !since.IsZero() {
			q.Set("updated_at_gt", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("apollo: activities: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("apollo: activities: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope apolloActivityPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("apollo: decode activities: %w", err)
		}
		collected = append(collected, envelope.Activities...)
		if envelope.Pagination.Page >= envelope.Pagination.TotalPages || len(envelope.Activities) < apolloAuditPageSize {
			break
		}
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapApolloActivity(&collected[i])
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

type apolloActivity struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Action    string `json:"action"`
	UpdatedAt string `json:"updated_at"`
	CreatedAt string `json:"created_at"`
	UserID    string `json:"user_id"`
	UserEmail string `json:"user_email"`
	ContactID string `json:"contact_id"`
}

type apolloActivityPage struct {
	Activities []apolloActivity `json:"activities"`
	Pagination struct {
		Page       int `json:"page"`
		PerPage    int `json:"per_page"`
		TotalPages int `json:"total_pages"`
		TotalCount int `json:"total_count"`
	} `json:"pagination"`
}

func mapApolloActivity(a *apolloActivity) *access.AuditLogEntry {
	if a == nil || strings.TrimSpace(a.ID) == "" {
		return nil
	}
	tsRaw := a.UpdatedAt
	if strings.TrimSpace(tsRaw) == "" {
		tsRaw = a.CreatedAt
	}
	ts := parseApolloTime(tsRaw)
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
		ActorEmail:       strings.TrimSpace(a.UserEmail),
		TargetExternalID: strings.TrimSpace(a.ContactID),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseApolloTime(s string) time.Time {
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

var _ access.AccessAuditor = (*ApolloAccessConnector)(nil)
