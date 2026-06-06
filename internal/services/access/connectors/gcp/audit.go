package gcp

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

const loggingBaseURL = "https://logging.googleapis.com"

// FetchAccessAuditLogs streams GCP Cloud Audit log entries
// (cloudaudit.googleapis.com) into the access audit pipeline.
// Implements access.AccessAuditor.
//
// Endpoint:
//
//	POST /v2/entries:list
//	Body: { "resourceNames": ["projects/{project}"],
//	 "filter": "logName=\"projects/{project}/logs/cloudaudit.googleapis.com%2Factivity\" AND timestamp>=\"{since}\"",
//	 "orderBy": "timestamp asc",
//	 "pageSize": 100,
//	 "pageToken": "..." }
//
// Pagination uses `nextPageToken`. The handler is called per page in
// chronological order; `nextSince` is the timestamp of the newest
// entry in the batch.
func (c *GCPAccessConnector) FetchAccessAuditLogs(
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
	client, err := c.cloudResourceClient(ctx, cfg, secrets)
	if err != nil {
		return err
	}

	filter := fmt.Sprintf(
		`logName="projects/%s/logs/cloudaudit.googleapis.com%%2Factivity"`,
		cfg.ProjectID,
	)
	if !since.IsZero() {
		filter += fmt.Sprintf(` AND timestamp>=%q`, since.UTC().Format(time.RFC3339))
	}

	cursor := since
	pageToken := ""
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		reqBody := map[string]interface{}{
			"resourceNames": []string{"projects/" + cfg.ProjectID},
			"filter":        filter,
			"orderBy":       "timestamp asc",
			"pageSize":      100,
		}
		if pageToken != "" {
			reqBody["pageToken"] = pageToken
		}
		raw, _ := json.Marshal(reqBody)
		endpoint := c.loggingURL("/v2/entries:list")
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("gcp: logging entries:list: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("gcp: logging entries:list status %d: %s", resp.StatusCode, string(body))
		}
		var page gcpLoggingPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("gcp: decode logging page: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Entries))
		batchMax := cursor
		for i := range page.Entries {
			entry := mapGCPLogEntry(&page.Entries[i])
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
		if strings.TrimSpace(page.NextPageToken) == "" {
			return nil
		}
		pageToken = page.NextPageToken
	}
}

// loggingURL returns the Cloud Logging endpoint, honouring urlOverride
// for tests so the existing httptest plumbing is reused.
func (c *GCPAccessConnector) loggingURL(path string) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/") + path
	}
	return loggingBaseURL + path
}

type gcpLoggingPage struct {
	Entries       []gcpLogEntry `json:"entries"`
	NextPageToken string        `json:"nextPageToken"`
}

type gcpLogEntry struct {
	InsertID     string                 `json:"insertId"`
	LogName      string                 `json:"logName"`
	Timestamp    string                 `json:"timestamp"`
	Severity     string                 `json:"severity"`
	ProtoPayload gcpProtoPayload        `json:"protoPayload"`
	Resource     map[string]interface{} `json:"resource"`
	JSONPayload  map[string]interface{} `json:"jsonPayload"`
}

type gcpProtoPayload struct {
	ServiceName        string `json:"serviceName"`
	MethodName         string `json:"methodName"`
	ResourceName       string `json:"resourceName"`
	AuthenticationInfo struct {
		PrincipalEmail   string `json:"principalEmail"`
		PrincipalSubject string `json:"principalSubject"`
	} `json:"authenticationInfo"`
	RequestMetadata struct {
		CallerIP                string `json:"callerIp"`
		CallerSuppliedUserAgent string `json:"callerSuppliedUserAgent"`
	} `json:"requestMetadata"`
	Status struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"status"`
}

func mapGCPLogEntry(e *gcpLogEntry) *access.AuditLogEntry {
	if e == nil || e.InsertID == "" {
		return nil
	}
	ts := parseGCPTime(e.Timestamp)
	if ts.IsZero() {
		return nil
	}
	outcome := "success"
	if e.ProtoPayload.Status.Code != 0 {
		outcome = "failure"
	}
	rawMap := map[string]interface{}{
		"log_name":     e.LogName,
		"service":      e.ProtoPayload.ServiceName,
		"method":       e.ProtoPayload.MethodName,
		"resource":     e.Resource,
		"json_payload": e.JSONPayload,
		"status":       e.ProtoPayload.Status,
	}
	actor := e.ProtoPayload.AuthenticationInfo.PrincipalEmail
	if actor == "" {
		actor = e.ProtoPayload.AuthenticationInfo.PrincipalSubject
	}
	return &access.AuditLogEntry{
		EventID:          e.InsertID,
		EventType:        e.ProtoPayload.ServiceName,
		Action:           e.ProtoPayload.MethodName,
		Timestamp:        ts,
		ActorExternalID:  actor,
		ActorEmail:       e.ProtoPayload.AuthenticationInfo.PrincipalEmail,
		TargetExternalID: e.ProtoPayload.ResourceName,
		IPAddress:        e.ProtoPayload.RequestMetadata.CallerIP,
		UserAgent:        e.ProtoPayload.RequestMetadata.CallerSuppliedUserAgent,
		Outcome:          outcome,
		RawData:          rawMap,
	}
}

// parseGCPTime parses Cloud Logging entry timestamps. Cloud Logging emits
// RFC3339 with nanosecond precision (e.g. 2024-01-15T10:30:45.123456789Z),
// which time.RFC3339 rejects, so RFC3339Nano is tried first. Results are
// normalized to UTC to match the other connectors' audit time parsers.
func parseGCPTime(s string) time.Time {
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

var _ access.AccessAuditor = (*GCPAccessConnector)(nil)
