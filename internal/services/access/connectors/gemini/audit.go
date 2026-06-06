package gemini

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

const (
	geminiAuditPageSize = 100
	geminiAuditMaxPages = 200
)

// FetchAccessAuditLogs streams Google Cloud Audit Logs (data_access,
// system_event) scoped to the operator's Vertex AI project into the
// access audit pipeline. Implements access.AccessAuditor.
//
// Endpoint:
//
//	POST /v2/entries:list  with resourceNames=projects/{project} +
//	     filter=logName=projects/{project}/logs/cloudaudit.googleapis.com%2Fdata_access
//	     + pageSize + pageToken
//
// OAuth2 bearer auth via GeminiAccessConnector.newRequest; projects
// without Cloud Logging API enabled surface 401/403/404 which soft-skip
// via access.ErrAuditNotAvailable.
func (c *GeminiAccessConnector) FetchAccessAuditLogs(
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
	endpoint := c.auditBaseURL() + "/v2/entries:list"

	filter := fmt.Sprintf(`logName="projects/%s/logs/cloudaudit.googleapis.com%%2Fdata_access"`, cfg.ProjectID)
	if !since.IsZero() {
		filter += fmt.Sprintf(` AND timestamp>=%q`, since.UTC().Format(time.RFC3339))
	}

	var collected []geminiAuditEntry
	pageToken := ""
	for page := 0; page < geminiAuditMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		reqBody := map[string]interface{}{
			"resourceNames": []string{"projects/" + cfg.ProjectID},
			"filter":        filter,
			"pageSize":      geminiAuditPageSize,
		}
		if pageToken != "" {
			reqBody["pageToken"] = pageToken
		}
		buf, _ := json.Marshal(reqBody)
		req, err := c.newRequest(ctx, secrets, http.MethodPost, endpoint)
		if err != nil {
			return err
		}
		req.Body = io.NopCloser(bytes.NewReader(buf))
		req.ContentLength = int64(len(buf))
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.client().Do(req)
		if err != nil {
			return fmt.Errorf("gemini: entries:list: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("gemini: entries:list: status %d: %s", resp.StatusCode, string(body))
		}
		var envelope geminiAuditPage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("gemini: decode entries:list: %w", err)
		}
		collected = append(collected, envelope.Entries...)
		if envelope.NextPageToken == "" {
			break
		}
		pageToken = envelope.NextPageToken
	}

	if len(collected) == 0 {
		return nil
	}
	batch := make([]*access.AuditLogEntry, 0, len(collected))
	batchMax := since
	for i := range collected {
		entry := mapGeminiAuditEntry(&collected[i])
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

type geminiAuditEntry struct {
	InsertID     string `json:"insertId"`
	LogName      string `json:"logName"`
	Timestamp    string `json:"timestamp"`
	ProtoPayload struct {
		MethodName         string `json:"methodName"`
		ResourceName       string `json:"resourceName"`
		AuthenticationInfo struct {
			PrincipalEmail string `json:"principalEmail"`
		} `json:"authenticationInfo"`
		RequestMetadata struct {
			CallerIP string `json:"callerIp"`
		} `json:"requestMetadata"`
	} `json:"protoPayload"`
}

type geminiAuditPage struct {
	Entries       []geminiAuditEntry `json:"entries"`
	NextPageToken string             `json:"nextPageToken"`
}

func mapGeminiAuditEntry(e *geminiAuditEntry) *access.AuditLogEntry {
	if e == nil || strings.TrimSpace(e.InsertID) == "" {
		return nil
	}
	ts := parseGeminiTime(e.Timestamp)
	if ts.IsZero() {
		return nil
	}
	raw, _ := json.Marshal(e)
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          strings.TrimSpace(e.InsertID),
		EventType:        strings.TrimSpace(e.ProtoPayload.MethodName),
		Action:           strings.TrimSpace(e.ProtoPayload.MethodName),
		Timestamp:        ts,
		ActorExternalID:  strings.TrimSpace(e.ProtoPayload.AuthenticationInfo.PrincipalEmail),
		ActorEmail:       strings.TrimSpace(e.ProtoPayload.AuthenticationInfo.PrincipalEmail),
		TargetExternalID: strings.TrimSpace(e.ProtoPayload.ResourceName),
		IPAddress:        strings.TrimSpace(e.ProtoPayload.RequestMetadata.CallerIP),
		Outcome:          "success",
		RawData:          rawMap,
	}
}

func parseGeminiTime(s string) time.Time {
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

var _ access.AccessAuditor = (*GeminiAccessConnector)(nil)
