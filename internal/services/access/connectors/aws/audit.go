package aws

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// cloudTrailBaseURL is the default regional CloudTrail endpoint
// template. Tests use the AWSAccessConnector.urlOverride field to
// redirect to an httptest.Server.
const cloudTrailBaseURL = "https://cloudtrail.us-east-1.amazonaws.com/"
const cloudTrailTarget = "CloudTrail_20131101.LookupEvents"

// FetchAccessAuditLogs streams AWS CloudTrail management events into
// the access audit pipeline via the LookupEvents JSON RPC API.
// Implements access.AccessAuditor.
//
// Endpoint:
//
//	POST https://cloudtrail.{region}.amazonaws.com/
//	X-Amz-Target: CloudTrail_20131101.LookupEvents
//	Body: { "StartTime": <unix>, "EndTime": <unix>, "MaxResults": 50,
//	 "NextToken": "..." }
//
// Pagination uses `NextToken`. The handler is called per page in
// chronological order; `nextSince` is the timestamp of the newest
// EventTime in the batch.
func (c *AWSAccessConnector) FetchAccessAuditLogs(
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
	cursor := since
	nextToken := ""
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		reqBody := map[string]interface{}{
			"MaxResults": 50,
		}
		if !since.IsZero() {
			reqBody["StartTime"] = since.Unix()
		}
		if nextToken != "" {
			reqBody["NextToken"] = nextToken
		}
		raw, _ := json.Marshal(reqBody)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cloudTrailEndpoint(), bytes.NewReader(raw))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-amz-json-1.1")
		req.Header.Set("X-Amz-Target", cloudTrailTarget)
		if err := signRequestSigV4(req, secrets.AccessKeyID, secrets.SecretAccessKey, defaultRegion, "cloudtrail", c.now()); err != nil {
			return fmt.Errorf("aws: sign: %w", err)
		}
		_ = cfg // cfg currently exposes only the role ARN; CloudTrail call uses defaultRegion.

		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("aws: cloudtrail: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("aws: cloudtrail status %d: %s", resp.StatusCode, string(body))
		}
		var page cloudTrailLookupResponse
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("aws: decode cloudtrail page: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Events))
		batchMax := cursor
		for i := range page.Events {
			entry := mapCloudTrailEvent(&page.Events[i])
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
		if strings.TrimSpace(page.NextToken) == "" {
			return nil
		}
		nextToken = page.NextToken
	}
}

func (c *AWSAccessConnector) cloudTrailEndpoint() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/") + "/"
	}
	return cloudTrailBaseURL
}

type cloudTrailLookupResponse struct {
	Events    []cloudTrailEvent `json:"Events"`
	NextToken string            `json:"NextToken"`
}

type cloudTrailEvent struct {
	EventID     string  `json:"EventId"`
	EventName   string  `json:"EventName"`
	EventTime   float64 `json:"EventTime"`
	Username    string  `json:"Username"`
	EventSource string  `json:"EventSource"`
	Resources   []struct {
		ResourceType string `json:"ResourceType"`
		ResourceName string `json:"ResourceName"`
	} `json:"Resources"`
	CloudTrailEvent string `json:"CloudTrailEvent"`
}

func mapCloudTrailEvent(e *cloudTrailEvent) *access.AuditLogEntry {
	if e == nil || e.EventID == "" {
		return nil
	}
	ts := time.Unix(int64(e.EventTime), 0).UTC()
	var targetID, targetType string
	if len(e.Resources) > 0 {
		targetID = e.Resources[0].ResourceName
		targetType = e.Resources[0].ResourceType
	}
	rawMap := map[string]interface{}{
		"EventName":   e.EventName,
		"EventSource": e.EventSource,
		"Resources":   e.Resources,
	}
	if e.CloudTrailEvent != "" {
		var inner map[string]interface{}
		_ = json.Unmarshal([]byte(e.CloudTrailEvent), &inner)
		if inner != nil {
			rawMap["cloudtrail_event"] = inner
		}
	}
	return &access.AuditLogEntry{
		EventID:          e.EventID,
		EventType:        e.EventSource,
		Action:           e.EventName,
		Timestamp:        ts,
		ActorEmail:       e.Username,
		ActorExternalID:  e.Username,
		TargetExternalID: targetID,
		TargetType:       targetType,
		Outcome:          "success",
		RawData:          rawMap,
	}
}

var _ access.AccessAuditor = (*AWSAccessConnector)(nil)
