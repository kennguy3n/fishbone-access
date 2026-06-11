package launchdarkly

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
	"github.com/kennguy3n/fishbone-access/internal/services/access/connectors/connutil"
)

const (
	launchDarklyAuditPageSize = 100
	launchDarklyAuditMaxPages = 200
)

// FetchAccessAuditLogs streams LaunchDarkly audit-log entries into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET /api/v2/auditlog?limit=100&offset=N&after={unixms}
//
// Authentication is the LaunchDarkly API key (Authorization header,
// no Bearer prefix). The audit-log API requires the "Read auditlog"
// member role; restricted keys receive 401 / 403 / 404 which the
// connector soft-skips via access.ErrAuditNotAvailable.
//
// Items are returned newest-first. To honour the AccessAuditor
// contract the connector buffers the full sweep, then walks the
// collection oldest-first into the handler exactly once so
// `nextSince` covers every yielded event. If any page fails the
// cursor stays where it was, so a retry replays the same window
// rather than silently skipping older entries.
func (c *LaunchDarklyAccessConnector) FetchAccessAuditLogs(
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
	base := c.baseURL() + "/api/v2/auditlog"

	var collected []launchDarklyAuditEntry
	offset := 0
	for pages := 0; pages < launchDarklyAuditMaxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("limit", fmt.Sprintf("%d", launchDarklyAuditPageSize))
		q.Set("offset", fmt.Sprintf("%d", offset))
		if !since.IsZero() {
			q.Set("after", fmt.Sprintf("%d", since.UTC().UnixMilli()))
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("launchdarkly: audit log: %w", err)
		}
		body, readErr := readLaunchDarklyBody(resp)
		if readErr != nil {
			return readErr
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("launchdarkly: audit log: status %d: %s", resp.StatusCode, string(body))
		}
		var p launchDarklyAuditPage
		if err := json.Unmarshal(body, &p); err != nil {
			return fmt.Errorf("launchdarkly: decode audit log: %w", err)
		}
		if len(p.Items) == 0 {
			break
		}
		collected = append(collected, p.Items...)
		if len(p.Items) < launchDarklyAuditPageSize {
			break
		}
		offset += len(p.Items)
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	// Newest-first → reverse to chronological.
	for i := len(collected) - 1; i >= 0; i-- {
		entry := mapLaunchDarklyAuditEntry(&collected[i])
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

type launchDarklyAuditPage struct {
	Items      []launchDarklyAuditEntry `json:"items"`
	TotalCount int                      `json:"totalCount"`
}

type launchDarklyAuditEntry struct {
	ID          string `json:"_id"`
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	Description string `json:"description"`
	ShortDesc   string `json:"shortDescription"`
	Date        int64  `json:"date"` // milliseconds since epoch
	Member      struct {
		ID    string `json:"_id"`
		Email string `json:"email"`
	} `json:"member"`
	Target struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
		Key  string `json:"key"`
	} `json:"target"`
	TitleVerb string `json:"titleVerb"`
}

func mapLaunchDarklyAuditEntry(e *launchDarklyAuditEntry) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.ID) == "" {
		return nil
	}
	// time.UnixMilli(0) returns 1970-01-01T00:00:00Z, not the zero time, so
	// a missing/zero Date would otherwise leak into the batch with a 1970
	// timestamp and poison the cursor. Drop the row instead.
	if e.Date == 0 {
		return nil
	}
	ts := time.UnixMilli(e.Date).UTC()
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	action := strings.TrimSpace(e.TitleVerb)
	if action == "" {
		action = strings.TrimSpace(e.Name)
	}
	return &access.AuditLogEntry{
		EventID:          e.ID,
		EventType:        strings.TrimSpace(e.Kind),
		Action:           action,
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.Member.ID),
		ActorEmail:       strings.TrimSpace(e.Member.Email),
		TargetExternalID: strings.TrimSpace(e.Target.Key),
		TargetType:       strings.TrimSpace(e.Target.Kind),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func readLaunchDarklyBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, errors.New("launchdarkly: empty response")
	}
	defer resp.Body.Close()
	return connutil.ReadBody(resp.Body)
}

var _ access.AccessAuditor = (*LaunchDarklyAccessConnector)(nil)
