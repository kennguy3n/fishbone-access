package wasabi

import (
	"context"
	"encoding/xml"
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
	wasabiCloudTrailDefaultURL = "https://cloudtrail.us-east-1.wasabisys.com/"
	wasabiCloudTrailAPIVersion = "2013-11-01"
	wasabiAuditMaxPages        = 200
)

// FetchAccessAuditLogs streams Wasabi CloudTrail-compatible
// "LookupEvents" entries into the access audit pipeline. Implements
// access.AccessAuditor.
//
// Endpoint:
//
//	POST https://cloudtrail.{region}.wasabisys.com/
//	Action=LookupEvents&MaxResults=50&...    (SigV4, service="cloudtrail")
//
// Wasabi exposes a CloudTrail-API compatible audit log; tenants
// without CloudTrail enabled receive AccessDenied / 401 / 403 / 404
// which the connector soft-skips via access.ErrAuditNotAvailable.
//
// Pagination uses CloudTrail's NextToken cursor. The connector
// buffers every page before invoking the handler so a partial sweep
// does not advance the persisted cursor.
func (c *WasabiAccessConnector) FetchAccessAuditLogs(
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

	var collected []wasabiCTEvent
	nextToken := ""
	for pages := 0; pages < wasabiAuditMaxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		params := url.Values{}
		params.Set("Action", "LookupEvents")
		params.Set("MaxResults", "50")
		params.Set("Version", wasabiCloudTrailAPIVersion)
		if !since.IsZero() {
			params.Set("StartTime", since.UTC().Format(time.RFC3339))
		}
		if nextToken != "" {
			params.Set("NextToken", nextToken)
		}
		body, status, err := c.callCloudTrail(ctx, secrets, params)
		if err != nil {
			return err
		}
		switch status {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if status < 200 || status >= 300 {
			lower := strings.ToLower(string(body))
			if strings.Contains(lower, "accessdenied") || strings.Contains(lower, "notenabled") {
				return access.ErrAuditNotAvailable
			}
			return fmt.Errorf("wasabi: audit log: status %d: %s", status, string(body))
		}
		var parsed wasabiLookupEventsResponse
		if err := xml.Unmarshal(body, &parsed); err != nil {
			return fmt.Errorf("wasabi: decode audit log: %w", err)
		}
		collected = append(collected, parsed.Result.Events...)
		if parsed.Result.NextToken == "" || len(parsed.Result.Events) == 0 {
			break
		}
		nextToken = parsed.Result.NextToken
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapWasabiCTEvent(&collected[i])
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

func (c *WasabiAccessConnector) cloudTrailURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/") + "/"
	}
	return wasabiCloudTrailDefaultURL
}

func (c *WasabiAccessConnector) callCloudTrail(ctx context.Context, secrets Secrets, params url.Values) ([]byte, int, error) {
	body := params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cloudTrailURL(), strings.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("Accept", "application/xml")
	if err := signRequestSigV4(req, secrets.AccessKeyID, secrets.SecretAccessKey, defaultRegion, "cloudtrail", c.now()); err != nil {
		return nil, 0, fmt.Errorf("wasabi: sign: %w", err)
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("wasabi: %s: network error", params.Get("Action"))
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return respBody, resp.StatusCode, nil
}

type wasabiLookupEventsResponse struct {
	XMLName xml.Name `xml:"LookupEventsResponse"`
	Result  struct {
		NextToken string          `xml:"NextToken"`
		Events    []wasabiCTEvent `xml:"Events>Event"`
	} `xml:"LookupEventsResult"`
}

type wasabiCTEvent struct {
	EventID     string `xml:"EventId"`
	EventName   string `xml:"EventName"`
	EventTime   string `xml:"EventTime"`
	Username    string `xml:"Username"`
	EventSource string `xml:"EventSource"`
	Resources   []struct {
		ResourceName string `xml:"ResourceName"`
		ResourceType string `xml:"ResourceType"`
	} `xml:"Resources>ResourceListEntry"`
	CloudTrailEvent string `xml:"CloudTrailEvent"`
}

func mapWasabiCTEvent(e *wasabiCTEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.EventID) == "" {
		return nil
	}
	ts := parseWasabiCTTime(e.EventTime)
	if ts.IsZero() {
		return nil
	}
	target := ""
	targetType := ""
	if len(e.Resources) > 0 {
		target = strings.TrimSpace(e.Resources[0].ResourceName)
		targetType = strings.TrimSpace(e.Resources[0].ResourceType)
	}
	rawMap := map[string]interface{}{
		"event_id":     e.EventID,
		"event_name":   e.EventName,
		"event_time":   e.EventTime,
		"event_source": e.EventSource,
		"username":     e.Username,
	}
	return &access.AuditLogEntry{
		EventID:          e.EventID,
		EventType:        strings.TrimSpace(e.EventName),
		Action:           strings.TrimSpace(e.EventName),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.Username),
		TargetExternalID: target,
		TargetType:       targetType,
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseWasabiCTTime(s string) time.Time {
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

var _ = errors.New

var _ access.AccessAuditor = (*WasabiAccessConnector)(nil)
