package azure

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

const activityLogAPIVersion = "2015-04-01"

// azureAuditMaxPages bounds the nextLink pagination walk as
// defense-in-depth: cursor pagination normally terminates when nextLink
// is empty, but this cap guarantees the loop cannot spin forever if a
// misbehaving upstream keeps issuing fresh nextLink cursors. Mirrors the
// explicit per-connector audit caps elsewhere in this batch and
// boxCollaborationsMaxPages. 1000 pages is far beyond any real activity
// log window.
const azureAuditMaxPages = 1000

// FetchAccessAuditLogs streams Azure Monitor Activity Log management
// events into the access audit pipeline. Implements
// access.AccessAuditor.
//
// Endpoint:
//
//	GET /subscriptions/{subId}/providers/Microsoft.Insights/eventtypes/management/values
//	 ?api-version=2015-04-01
//	 &$filter=eventTimestamp ge '{since}'
//
// Pagination uses `nextLink`. The handler is called per page in
// chronological order; `nextSince` is the timestamp of the newest
// eventTimestamp in the batch.
func (c *AzureAccessConnector) FetchAccessAuditLogs(
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
	client := c.armClient(ctx, cfg, secrets)

	filter := ""
	if !since.IsZero() {
		filter = fmt.Sprintf("eventTimestamp ge '%s'", since.UTC().Format(time.RFC3339))
	}
	path := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Insights/eventtypes/management/values?api-version=%s",
		url.PathEscape(cfg.SubscriptionID), activityLogAPIVersion)
	if filter != "" {
		path += "&$filter=" + url.QueryEscape(filter)
	}

	cursor := since
	next := c.armURL(path)
	for page := 0; next != "" && page < azureAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("azure: activity log: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("azure: activity log status %d: %s", resp.StatusCode, string(body))
		}
		var page azureActivityLogResponse
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("azure: decode activity log page: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Value))
		batchMax := cursor
		for i := range page.Value {
			entry := mapAzureActivityEvent(&page.Value[i])
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
		if page.NextLink == "" {
			return nil
		}
		// NextLink may be absolute; in tests we re-anchor to the
		// urlOverride so the redirected server still receives it.
		if c.urlOverride != "" && strings.HasPrefix(page.NextLink, defaultARMBaseURL) {
			next = c.urlOverride + strings.TrimPrefix(page.NextLink, defaultARMBaseURL)
		} else {
			next = page.NextLink
		}
	}
	return nil
}

type azureActivityLogResponse struct {
	Value    []azureActivityEvent `json:"value"`
	NextLink string               `json:"nextLink"`
}

type azureActivityEvent struct {
	EventDataID    string `json:"eventDataId"`
	EventTimestamp string `json:"eventTimestamp"`
	OperationName  struct {
		Value          string `json:"value"`
		LocalizedValue string `json:"localizedValue"`
	} `json:"operationName"`
	Status struct {
		Value string `json:"value"`
	} `json:"status"`
	Caller       string `json:"caller"`
	ResourceID   string `json:"resourceId"`
	ResourceType struct {
		Value string `json:"value"`
	} `json:"resourceType"`
	HTTPRequest struct {
		ClientIPAddress string `json:"clientIpAddress"`
	} `json:"httpRequest"`
	Category struct {
		Value string `json:"value"`
	} `json:"category"`
}

func mapAzureActivityEvent(e *azureActivityEvent) *access.AuditLogEntry {
	if e == nil || e.EventDataID == "" {
		return nil
	}
	ts := parseAzureTime(e.EventTimestamp)
	if ts.IsZero() {
		// Drop events whose timestamp cannot be parsed: a zero
		// timestamp would not advance the watermark cursor and would
		// be re-fetched every sync cycle. Matches the other audit
		// mappers in this package set.
		return nil
	}
	outcome := strings.ToLower(strings.TrimSpace(e.Status.Value))
	if outcome == "" {
		outcome = "unknown"
	}
	rawMap := map[string]interface{}{
		"operation_name": e.OperationName.Value,
		"category":       e.Category.Value,
		"resource_type":  e.ResourceType.Value,
		"localized_name": e.OperationName.LocalizedValue,
	}
	return &access.AuditLogEntry{
		EventID:          e.EventDataID,
		EventType:        e.Category.Value,
		Action:           e.OperationName.Value,
		Timestamp:        ts,
		ActorExternalID:  e.Caller,
		ActorEmail:       e.Caller,
		TargetExternalID: e.ResourceID,
		TargetType:       e.ResourceType.Value,
		IPAddress:        e.HTTPRequest.ClientIPAddress,
		Outcome:          outcome,
		RawData:          rawMap,
	}
}

// parseAzureTime parses Azure activity-log timestamps, trying
// RFC3339Nano (fractional seconds) before RFC3339, matching the
// parseXxxTime helpers in the other connectors of this batch. RFC3339
// alone already tolerates fractional seconds on input, so this is a
// consistency wrapper; it returns the zero time when the input is empty
// or unparseable so callers can drop the event.
func parseAzureTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if ts, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return ts
	}
	if ts, err := time.Parse(time.RFC3339, s); err == nil {
		return ts
	}
	return time.Time{}
}

var _ access.AccessAuditor = (*AzureAccessConnector)(nil)
