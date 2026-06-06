package cloudflare

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

const (
	cloudflareAuditPageSize = 100
	// cloudflareAuditMaxPages bounds pagination so an inflated
	// ResultInfo.TotalPages (a broad multi-year window, or an API bug)
	// cannot pin a worker goroutine in an excessive request loop. Matches
	// the cap used by every other audit connector in this PR
	// (buildium/checkpoint/circleci/clio/close/cloudsigma/clickup = 200).
	cloudflareAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Cloudflare audit log events into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /accounts/{account_id}/audit_logs?since={since}&page={n}&per_page=100
//
// Cloudflare paginates by page/per_page; the handler is called once
// per provider page in chronological order so callers can persist the
// monotonic `nextSince` cursor between runs.
func (c *CloudflareAccessConnector) FetchAccessAuditLogs(
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
	for page := 1; page <= cloudflareAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("per_page", strconv.Itoa(cloudflareAuditPageSize))
		q.Set("page", strconv.Itoa(page))
		q.Set("direction", "asc")
		if !since.IsZero() {
			q.Set("since", since.UTC().Format(time.RFC3339))
		}
		path := "/accounts/" + url.PathEscape(cfg.AccountID) + "/audit_logs?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, cfg, http.MethodGet, path)
		if err != nil {
			return err
		}
		httpResp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("cloudflare: audit logs: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
		_ = httpResp.Body.Close()
		// Tokens without audit-log scope (or accounts on plans that do not
		// surface the feed) return 401 / 403 / 404; soft-skip those via
		// access.ErrAuditNotAvailable per docs/architecture.md §2 instead of
		// surfacing a hard error, matching every other audit connector.
		switch httpResp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
			return fmt.Errorf("cloudflare: audit logs: status %d: %s", httpResp.StatusCode, string(body))
		}
		var resp cfAuditLogPage
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("cloudflare: decode audit logs: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(resp.Result))
		batchMax := cursor
		for i := range resp.Result {
			entry := mapCloudflareAuditEvent(&resp.Result[i])
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
		if resp.ResultInfo.TotalPages <= page || len(resp.Result) == 0 {
			return nil
		}
	}
	return nil
}

type cfAuditLogPage struct {
	Result     []cfAuditLog `json:"result"`
	ResultInfo struct {
		Page       int `json:"page"`
		PerPage    int `json:"per_page"`
		TotalPages int `json:"total_pages"`
		Count      int `json:"count"`
		TotalCount int `json:"total_count"`
	} `json:"result_info"`
	Success bool             `json:"success"`
	Errors  []map[string]any `json:"errors"`
}

type cfAuditLog struct {
	ID     string `json:"id"`
	When   string `json:"when"`
	Action struct {
		Type   string `json:"type"`
		Result bool   `json:"result"`
	} `json:"action"`
	Actor struct {
		ID    string `json:"id"`
		Type  string `json:"type"`
		Email string `json:"email"`
		IP    string `json:"ip"`
	} `json:"actor"`
	Resource struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"resource"`
	UserAgent string `json:"user_agent"`
}

func mapCloudflareAuditEvent(e *cfAuditLog) *access.AuditLogEntry {
	if e == nil || e.ID == "" {
		return nil
	}
	ts, err := time.Parse(time.RFC3339, e.When)
	if err != nil || ts.IsZero() {
		// An unparseable/absent `when` cannot advance the watermark
		// cursor and would be persisted as a bogus 0001-01-01 entry,
		// so drop it — consistent with every other connector's audit
		// mapper.
		return nil
	}
	ts = ts.UTC()
	outcome := "success"
	if !e.Action.Result {
		outcome = "failure"
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        e.Action.Type,
		Action:           e.Action.Type,
		Timestamp:        ts,
		ActorExternalID:  e.Actor.ID,
		ActorEmail:       strings.TrimSpace(e.Actor.Email),
		TargetExternalID: e.Resource.ID,
		TargetType:       e.Resource.Type,
		IPAddress:        e.Actor.IP,
		UserAgent:        e.UserAgent,
		Outcome:          outcome,
		RawData:          rawMap,
	}
}

var _ access.AccessAuditor = (*CloudflareAccessConnector)(nil)
