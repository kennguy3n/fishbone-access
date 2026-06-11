package docker_hub

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
	"github.com/kennguy3n/fishbone-access/internal/services/access/httputil"
)

const (
	dockerAuditPageSize = 100
	dockerAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Docker Hub organization audit-log
// entries into the access audit pipeline. Implements
// access.AccessAuditor.
//
// Endpoint (Docker Hub):
//
//	GET /v2/auditlogs/{org}/?page_size=100&page=N&from={iso}
//
// Authentication is the JWT bearer token returned by
// POST /v2/users/login (the same flow connector.go already uses).
// Audit log access is restricted to organisations on the Business
// plan; Docker IDs / Personal accounts and Team-plan orgs receive
// 401 / 403 / 404 which the connector soft-skips via
// access.ErrAuditNotAvailable.
//
// To honour the AccessAuditor contract under multi-page sweeps the
// connector buffers every page before advancing the persisted
// cursor: if any page fails the cursor stays where it was, so a
// retry replays the same window rather than silently skipping older
// entries below the persisted cursor.
func (c *DockerHubAccessConnector) FetchAccessAuditLogs(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	sincePartitions map[string]time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	token, err := c.login(ctx, secrets)
	if err != nil {
		// Treat login auth failures as soft-skip — the tenant
		// might be on a plan that disallows audit access.
		if strings.Contains(err.Error(), "status 401") ||
			strings.Contains(err.Error(), "status 403") {
			return access.ErrAuditNotAvailable
		}
		return err
	}

	since := sincePartitions[access.DefaultAuditPartition]
	base := fmt.Sprintf("%s/v2/auditlogs/%s/", c.baseURL(),
		url.PathEscape(strings.TrimSpace(cfg.Organization)))

	var collected []dockerAuditEntry
	page := 1
	for pages := 0; pages < dockerAuditMaxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("page_size", fmt.Sprintf("%d", dockerAuditPageSize))
		if !since.IsZero() {
			q.Set("from", since.UTC().Format(time.RFC3339))
		}
		req, err := c.newRequest(ctx, token, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("docker_hub: audit log: %w", err)
		}
		body, readErr := readDockerHubBody(resp)
		if readErr != nil {
			return readErr
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("docker_hub: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var p dockerAuditPage
		if err := json.Unmarshal(body, &p); err != nil {
			return fmt.Errorf("docker_hub: decode audit log: %w", err)
		}
		collected = append(collected, p.Logs...)
		if p.Next == "" && len(p.Logs) < dockerAuditPageSize {
			break
		}
		if len(p.Logs) == 0 {
			break
		}
		page++
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapDockerAuditEntry(&collected[i])
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

type dockerAuditPage struct {
	Count int                `json:"count"`
	Next  string             `json:"next"`
	Logs  []dockerAuditEntry `json:"logs"`
}

type dockerAuditEntry struct {
	Action     string `json:"action"`
	ActionDesc string `json:"action_description,omitempty"`
	Actor      string `json:"actor"`
	Data       struct {
		Digest    string `json:"digest,omitempty"`
		Namespace string `json:"namespace,omitempty"`
		Repo      string `json:"repository,omitempty"`
		Tag       string `json:"tag,omitempty"`
		Member    string `json:"member,omitempty"`
		Team      string `json:"team,omitempty"`
	} `json:"data"`
	Account string `json:"account"`
	Time    string `json:"timestamp"`
}

func mapDockerAuditEntry(e *dockerAuditEntry) *access.AuditLogEntry {
	if e == nil {
		return nil
	}
	ts := parseDockerAuditTime(e.Time)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	target := strings.TrimSpace(e.Data.Repo)
	targetType := "repository"
	if target == "" {
		target = strings.TrimSpace(e.Data.Member)
		if target != "" {
			targetType = "member"
		}
	}
	if target == "" {
		target = strings.TrimSpace(e.Data.Team)
		if target != "" {
			targetType = "team"
		}
	}
	id := fmt.Sprintf("%s/%s/%s", strings.TrimSpace(e.Action), e.Time, target)
	return &access.AuditLogEntry{
		EventID:          id,
		EventType:        strings.TrimSpace(e.Action),
		Action:           strings.TrimSpace(e.Action),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.Actor),
		TargetExternalID: target,
		TargetType:       targetType,
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseDockerAuditTime(s string) time.Time {
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

func readDockerHubBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, errors.New("docker_hub: empty response")
	}
	defer resp.Body.Close()
	return httputil.ReadAllLimited(resp.Body, 0)
}

var _ access.AccessAuditor = (*DockerHubAccessConnector)(nil)
