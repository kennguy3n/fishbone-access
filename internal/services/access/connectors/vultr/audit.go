package vultr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const (
	vultrAuditPageSize = 100
	vultrAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Vultr account audit events into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /v2/audit-log?per_page=100&cursor={cursor}
//
// Vultr exposes account activity (logins, resource mutations, sub-user
// changes) via /v2/audit-log with bearer auth. API keys without the
// admin / sub-user read scope receive 401 / 403 / 404 which the
// connector soft-skips via access.ErrAuditNotAvailable.
//
// Pagination uses Vultr's opaque cursor in `meta.links.next`. The
// connector buffers every page before invoking the handler so a
// partial sweep does not advance the persisted cursor.
func (c *VultrAccessConnector) FetchAccessAuditLogs(
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

	var collected []vultrAuditEvent
	cursor := ""
	for pages := 0; pages < vultrAuditMaxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("per_page", fmt.Sprintf("%d", vultrAuditPageSize))
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, c.baseURL()+"/v2/audit-log?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("vultr: audit log: %w", err)
		}
		body, readErr := readVultrAuditBody(resp)
		if readErr != nil {
			return readErr
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("vultr: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var parsed vultrAuditResponse
		if err := json.Unmarshal(body, &parsed); err != nil {
			return fmt.Errorf("vultr: decode audit log: %w", err)
		}
		olderThanCursor := false
		for i := range parsed.AuditLogs {
			ts := parseVultrAuditTime(parsed.AuditLogs[i].Timestamp)
			if !since.IsZero() && !ts.IsZero() && !ts.After(since) {
				olderThanCursor = true
				continue
			}
			collected = append(collected, parsed.AuditLogs[i])
		}
		next := parsed.Meta.Links.Next
		if olderThanCursor || next == "" {
			break
		}
		cursor = next
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapVultrAuditEvent(&collected[i])
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

type vultrAuditResponse struct {
	AuditLogs []vultrAuditEvent `json:"audit_logs"`
	Meta      struct {
		Links struct {
			Next string `json:"next,omitempty"`
			Prev string `json:"prev,omitempty"`
		} `json:"links"`
	} `json:"meta"`
}

type vultrAuditEvent struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Description string `json:"description"`
	UserID      string `json:"user_id"`
	UserName    string `json:"user_name"`
	IP          string `json:"ip"`
	Timestamp   string `json:"timestamp"`
}

func mapVultrAuditEvent(e *vultrAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	ts := parseVultrAuditTime(e.Timestamp)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:         e.ID,
		EventType:       strings.TrimSpace(e.Type),
		Action:          strings.TrimSpace(e.Type),
		Timestamp:       ts,
		ActorExternalID: strings.TrimSpace(e.UserID),
		IPAddress:       strings.TrimSpace(e.IP),
		Outcome:         "success",
		RawData:         rawMap,
	}
}

func parseVultrAuditTime(s string) time.Time {
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

func readVultrAuditBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, errors.New("vultr: empty response")
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

var _ access.AccessAuditor = (*VultrAccessConnector)(nil)
