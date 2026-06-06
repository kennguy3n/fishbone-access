package alibaba

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
	actionTrailDefaultURL = "https://actiontrail.aliyuncs.com/"
	actionTrailAPIVersion = "2020-07-06"
	alibabaAuditMaxRows   = 50
	alibabaAuditMaxPages  = 200
)

// FetchAccessAuditLogs streams Alibaba Cloud ActionTrail "events"
// into the access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	GET https://actiontrail.aliyuncs.com/?Action=LookupEvents&...
//
// Authentication uses the same HMAC-SHA1 signature scheme as the
// existing RAM `ListUsers` call (shared `sign` helper).
//
// Accounts without ActionTrail enabled return AccessDenied / 403 /
// 404, which the connector soft-skips via access.ErrAuditNotAvailable.
//
// Pagination uses the ActionTrail NextToken cursor. The connector
// buffers every page before invoking the handler so a partial sweep
// does not advance the persisted cursor.
func (c *AlibabaAccessConnector) FetchAccessAuditLogs(
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

	var collected []alibabaAuditEvent
	nextToken := ""
	for pages := 0; pages < alibabaAuditMaxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		extra := map[string]string{
			"MaxResults": fmt.Sprintf("%d", alibabaAuditMaxRows),
		}
		if !since.IsZero() {
			extra["StartTime"] = since.UTC().Format("2006-01-02T15:04:05Z")
			extra["EndTime"] = c.now().UTC().Format("2006-01-02T15:04:05Z")
		}
		if nextToken != "" {
			extra["NextToken"] = nextToken
		}
		body, status, err := c.callActionTrail(ctx, secrets, "LookupEvents", extra)
		if err != nil {
			return err
		}
		switch status {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if status < 200 || status >= 300 {
			return fmt.Errorf("alibaba: audit log: status %d: %s", status, string(body))
		}
		var parsed alibabaAuditResponse
		if err := json.Unmarshal(body, &parsed); err != nil {
			return fmt.Errorf("alibaba: decode audit log: %w", err)
		}
		if parsed.Code != "" {
			lower := strings.ToLower(parsed.Code)
			if strings.Contains(lower, "denied") ||
				strings.Contains(lower, "forbidden") ||
				strings.Contains(lower, "notenabled") {
				return access.ErrAuditNotAvailable
			}
			return fmt.Errorf("alibaba: audit log: code %s: %s", parsed.Code, parsed.Message)
		}
		collected = append(collected, parsed.Events...)
		if parsed.NextToken == "" || len(parsed.Events) == 0 {
			break
		}
		nextToken = parsed.NextToken
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapAlibabaAuditEvent(&collected[i])
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

func (c *AlibabaAccessConnector) actionTrailBaseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/") + "/"
	}
	return actionTrailDefaultURL
}

func (c *AlibabaAccessConnector) callActionTrail(ctx context.Context, secrets Secrets, action string, extra map[string]string) ([]byte, int, error) {
	params := map[string]string{
		"Format":           "JSON",
		"Version":          actionTrailAPIVersion,
		"AccessKeyId":      strings.TrimSpace(secrets.AccessKeyID),
		"SignatureMethod":  signatureMethod,
		"Timestamp":        c.now().UTC().Format("2006-01-02T15:04:05Z"),
		"SignatureVersion": signatureVersion,
		"SignatureNonce":   c.nonce(),
		"Action":           action,
	}
	for k, v := range extra {
		params[k] = v
	}
	signature := sign(strings.TrimSpace(secrets.AccessKeySecret), params, http.MethodGet)
	params["Signature"] = signature

	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	full := c.actionTrailBaseURL() + "?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("alibaba: %s: network error", action)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return body, resp.StatusCode, nil
}

type alibabaAuditResponse struct {
	Code      string              `json:"Code,omitempty"`
	Message   string              `json:"Message,omitempty"`
	NextToken string              `json:"NextToken,omitempty"`
	Events    []alibabaAuditEvent `json:"Events"`
}

type alibabaAuditEvent struct {
	EventID           string                 `json:"eventId"`
	EventName         string                 `json:"eventName"`
	EventTime         string                 `json:"eventTime"`
	EventSource       string                 `json:"eventSource"`
	ServiceName       string                 `json:"serviceName"`
	AcsRegion         string                 `json:"acsRegion"`
	SourceIPAddress   string                 `json:"sourceIpAddress"`
	UserIdentity      map[string]interface{} `json:"userIdentity"`
	RequestParameters map[string]interface{} `json:"requestParameters,omitempty"`
	ErrorCode         string                 `json:"errorCode,omitempty"`
	ErrorMessage      string                 `json:"errorMessage,omitempty"`
	ResourceName      string                 `json:"resourceName,omitempty"`
	ResourceType      string                 `json:"resourceType,omitempty"`
}

func mapAlibabaAuditEvent(e *alibabaAuditEvent) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.EventID) == "" {
		return nil
	}
	ts := parseAlibabaAuditTime(e.EventTime)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	outcome := "success"
	if strings.TrimSpace(e.ErrorCode) != "" {
		outcome = "failure"
	}
	actorID := ""
	if e.UserIdentity != nil {
		if v, ok := e.UserIdentity["principalId"].(string); ok {
			actorID = v
		} else if v, ok := e.UserIdentity["userName"].(string); ok {
			actorID = v
		}
	}
	return &access.AuditLogEntry{
		EventID:          e.EventID,
		EventType:        strings.TrimSpace(e.EventName),
		Action:           strings.TrimSpace(e.EventName),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(actorID),
		TargetExternalID: strings.TrimSpace(e.ResourceName),
		TargetType:       strings.TrimSpace(e.ResourceType),
		IPAddress:        strings.TrimSpace(e.SourceIPAddress),
		Outcome:          outcome,
		RawData:          rawMap,
	}
}

func parseAlibabaAuditTime(s string) time.Time {
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
	if ts, err := time.Parse("2006-01-02T15:04:05Z", s); err == nil {
		return ts.UTC()
	}
	return time.Time{}
}

var _ access.AccessAuditor = (*AlibabaAccessConnector)(nil)
