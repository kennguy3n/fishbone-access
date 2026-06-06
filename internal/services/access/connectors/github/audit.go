package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// FetchAccessAuditLogs streams GitHub organization audit log events
// into the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /orgs/{org}/audit-log?phrase=created:>={since}&per_page=100&order=asc
//
// The cursor filter is inclusive (created:>=) on purpose: a strict
// created:> could drop events that share the exact second of the last
// cursor. Re-fetching the boundary event is harmless because the audit
// pipeline de-duplicates by EventID, so inclusive is the safe choice.
//
// Pagination uses RFC-5988 Link: rel="next" headers. If the
// organization is not on a plan that exposes audit logs (e.g.
// 404/403), the call collapses to access.ErrAuditNotAvailable.
func (c *GitHubAccessConnector) FetchAccessAuditLogs(
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

	q := url.Values{}
	q.Set("per_page", "100")
	q.Set("order", "asc")
	if !since.IsZero() {
		q.Set("phrase", fmt.Sprintf("created:>=%s", since.UTC().Format(time.RFC3339)))
	}
	nextURL := fmt.Sprintf("%s/orgs/%s/audit-log?%s", c.baseURL(), url.PathEscape(cfg.Organization), q.Encode())

	cursor := since
	for nextURL != "" {
		if err := ctx.Err(); err != nil {
			return err
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, nextURL)
		if err != nil {
			return err
		}
		resp, doErr := c.doRaw(req)
		if resp != nil && (resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden) {
			return access.ErrAuditNotAvailable
		}
		if doErr != nil {
			return doErr
		}
		var page []githubAuditEntry
		if err := json.Unmarshal(resp.Body, &page); err != nil {
			return fmt.Errorf("github: decode audit page: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page))
		batchMax := cursor
		for i := range page {
			entry := mapGithubAuditEntry(&page[i])
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
		next := parseNextLink(resp.Header.Get("Link"))
		if next != "" && c.urlOverride != "" {
			next = strings.Replace(next, defaultBaseURL, strings.TrimRight(c.urlOverride, "/"), 1)
		}
		if next == "" {
			return nil
		}
		nextURL = next
	}
	return errors.New("github: audit log pagination ended unexpectedly")
}

type githubAuditEntry struct {
	DocumentID string `json:"_document_id"`
	Action     string `json:"action"`
	Actor      string `json:"actor"`
	ActorID    int64  `json:"actor_id"`
	UserAgent  string `json:"user_agent"`
	ActorIP    string `json:"actor_ip"`
	CreatedAt  int64  `json:"created_at"`
	User       string `json:"user"`
	Repo       string `json:"repo"`
	Org        string `json:"org"`
	Team       string `json:"team"`
}

func mapGithubAuditEntry(e *githubAuditEntry) *access.AuditLogEntry {
	if e == nil || e.DocumentID == "" {
		return nil
	}
	ts := time.UnixMilli(e.CreatedAt).UTC()
	var targetID, targetType string
	switch {
	case e.User != "":
		targetID = e.User
		targetType = "user"
	case e.Team != "":
		targetID = e.Team
		targetType = "team"
	case e.Repo != "":
		targetID = e.Repo
		targetType = "repo"
	case e.Org != "":
		targetID = e.Org
		targetType = "org"
	}
	return &access.AuditLogEntry{
		EventID:          e.DocumentID,
		EventType:        e.Action,
		Action:           e.Action,
		Timestamp:        ts,
		ActorExternalID:  e.Actor,
		ActorEmail:       e.Actor,
		TargetExternalID: targetID,
		TargetType:       targetType,
		IPAddress:        e.ActorIP,
		UserAgent:        e.UserAgent,
		Outcome:          "success",
	}
}

var _ access.AccessAuditor = (*GitHubAccessConnector)(nil)
