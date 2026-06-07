package google_workspace

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// reportsBaseURL is the Admin SDK Reports API root. Overridden in
// tests via httpClientFor + a URL-rewriting fake client (no
// reportsBaseURL override is needed because nextPageToken is opaque
// and we control the full URL ourselves).
const reportsBaseURL = "https://admin.googleapis.com/admin/reports/v1"

// gwAuditMaxPages bounds a single audit sweep so a Reports API that keeps
// returning a non-empty nextPageToken (or a server-side cursor bug) cannot
// spin the pagination loop forever; mirrors the cap used by the other
// paginated audit connectors in this family. Because the watermark advances
// per page (handler is called with the batch's newest timestamp), stopping at
// the cap simply defers the remaining pages to the next sync cycle.
const gwAuditMaxPages = 200

// FetchAccessAuditLogs streams login activities from the Admin SDK
// Reports API back into the access audit pipeline. Implements
// access.AccessAuditor.
//
// Endpoint:
//
//	GET /admin/reports/v1/activity/users/all/applications/login
//	 ?startTime={since}&maxResults=1000&pageToken={cursor}
//
// Pagination uses `nextPageToken`. The handler is called once per
// page in chronological order; `nextSince` is the timestamp of the
// newest entry in the batch.
func (c *GoogleWorkspaceAccessConnector) FetchAccessAuditLogs(
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
	client, err := c.reportsClient(ctx, cfg, secrets)
	if err != nil {
		return err
	}

	cursor := since
	pageToken := ""
	for pageNum := 0; pageNum < gwAuditMaxPages; pageNum++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		u, err := url.Parse(reportsBaseURL + "/activity/users/all/applications/login")
		if err != nil {
			return err
		}
		q := u.Query()
		q.Set("maxResults", "1000")
		if !since.IsZero() {
			q.Set("startTime", since.UTC().Format(time.RFC3339))
		}
		if pageToken != "" {
			q.Set("pageToken", pageToken)
		}
		u.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("google_workspace: reports activity: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 50<<20))
		_ = resp.Body.Close()
		// 401/403 (token lacks the reports scope / caller is not an
		// auditor) and 404 (tenant has no audit surface) are not hard
		// failures: the AccessAuditor contract requires them to be
		// soft-skipped so the worker drops the tenant instead of
		// retrying forever. Every other audit connector does the same.
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("google_workspace: reports activity: status %d: %s", resp.StatusCode, string(body))
		}
		var page struct {
			Items         []reportsActivity `json:"items"`
			NextPageToken string            `json:"nextPageToken"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("google_workspace: decode reports page: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Items))
		batchMax := cursor
		for i := range page.Items {
			entry := mapReportsActivity(&page.Items[i])
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
		if page.NextPageToken == "" {
			return nil
		}
		pageToken = page.NextPageToken
	}
	return nil
}

type reportsActivity struct {
	ID struct {
		Time            string `json:"time"`
		UniqueQualifier string `json:"uniqueQualifier"`
		ApplicationName string `json:"applicationName"`
	} `json:"id"`
	Actor struct {
		Email      string `json:"email"`
		ProfileID  string `json:"profileId"`
		CallerType string `json:"callerType"`
	} `json:"actor"`
	IPAddress string `json:"ipAddress"`
	Events    []struct {
		Type       string `json:"type"`
		Name       string `json:"name"`
		Parameters []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"parameters"`
	} `json:"events"`
}

func mapReportsActivity(a *reportsActivity) *access.AuditLogEntry {
	if a == nil || a.ID.UniqueQualifier == "" {
		return nil
	}
	ts, _ := time.Parse(time.RFC3339, a.ID.Time)
	if ts.IsZero() {
		// Drop events whose timestamp cannot be parsed: a zero
		// timestamp would not advance the watermark cursor and would
		// be re-fetched every sync cycle. Matches the other audit
		// mappers in this batch.
		return nil
	}
	eventType := a.ID.ApplicationName
	action := ""
	outcome := ""
	if len(a.Events) > 0 {
		action = a.Events[0].Name
		for _, p := range a.Events[0].Parameters {
			if p.Name == "login_failure_type" && p.Value != "" {
				outcome = "failure"
			}
		}
	}
	if outcome == "" {
		outcome = "success"
	}
	raw, _ := json.Marshal(a)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:         a.ID.UniqueQualifier,
		EventType:       eventType,
		Action:          action,
		Timestamp:       ts,
		ActorExternalID: a.Actor.ProfileID,
		ActorEmail:      a.Actor.Email,
		IPAddress:       a.IPAddress,
		Outcome:         outcome,
		RawData:         rawMap,
	}
}

var _ access.AccessAuditor = (*GoogleWorkspaceAccessConnector)(nil)
