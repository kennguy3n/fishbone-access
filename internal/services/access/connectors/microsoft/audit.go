package microsoft

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// Microsoft Graph audit partition keys. These MUST be stable strings:
// the worker uses them as map keys in access_sync_state to track each
// endpoint's cursor independently. Renaming a key would orphan the
// existing cursor and trigger a full backfill on the next run.
const (
	auditPartitionSignIns         = "microsoft/signIns"
	auditPartitionDirectoryAudits = "microsoft/directoryAudits"
)

// FetchAccessAuditLogs streams sign-in + directoryAudit events from Microsoft
// Graph back into the access audit pipeline. Implements
// access.AccessAuditor.
//
// Endpoints (docs/architecture.md §2):
//
//   - GET /auditLogs/signIns?$filter=createdDateTime ge {since}
//   - GET /auditLogs/directoryAudits?$filter=activityDateTime ge {since}
//
// Pagination uses `@odata.nextLink`. The handler is called once per page in
// chronological order; the handler receives the per-endpoint partition key
// so the worker can advance each cursor independently.
func (c *M365AccessConnector) FetchAccessAuditLogs(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	sincePartitions map[string]time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	client := c.graphClient(ctx, cfg, secrets)

	for _, ep := range []struct {
		path         string
		tsField      string
		mapFunc      func(raw json.RawMessage) (*access.AuditLogEntry, error)
		eventKind    string
		partitionKey string
	}{
		{
			path:         "/auditLogs/signIns",
			tsField:      "createdDateTime",
			mapFunc:      mapGraphSignIn,
			eventKind:    "signIn",
			partitionKey: auditPartitionSignIns,
		},
		{
			path:         "/auditLogs/directoryAudits",
			tsField:      "activityDateTime",
			mapFunc:      mapGraphDirectoryAudit,
			eventKind:    "directoryAudit",
			partitionKey: auditPartitionDirectoryAudits,
		},
	} {
		since := sincePartitions[ep.partitionKey]
		// cursor MUST reset per endpoint. Each endpoint paginates
		// independently from its own partition's `since`, so the
		// handler's nextSince must reflect that endpoint's progress
		// only. The partitionKey passed to handler lets the worker
		// track per-partition cursors in access_sync_state and
		// prevents a fast-moving partition's max timestamp from
		// shadowing a slower partition's progress on partial failure.
		cursor := since
		next, err := buildAuditStartURL(ep.path, ep.tsField, since)
		if err != nil {
			return err
		}
		for next != "" {
			if err := ctx.Err(); err != nil {
				return err
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
			if err != nil {
				return err
			}
			body, err := doJSON(client, req)
			if err != nil {
				return fmt.Errorf("microsoft: %s: %w", ep.path, err)
			}
			var page struct {
				Value    []json.RawMessage `json:"value"`
				NextLink string            `json:"@odata.nextLink"`
			}
			if err := json.Unmarshal(body, &page); err != nil {
				return fmt.Errorf("microsoft: decode %s page: %w", ep.path, err)
			}
			batch := make([]*access.AuditLogEntry, 0, len(page.Value))
			batchMax := cursor
			for _, raw := range page.Value {
				entry, err := ep.mapFunc(raw)
				if err != nil {
					continue
				}
				if entry == nil {
					continue
				}
				if entry.Timestamp.After(batchMax) {
					batchMax = entry.Timestamp
				}
				batch = append(batch, entry)
			}
			if err := handler(batch, batchMax, ep.partitionKey); err != nil {
				return err
			}
			cursor = batchMax
			next = page.NextLink
		}
	}
	return nil
}

func buildAuditStartURL(path, tsField string, since time.Time) (string, error) {
	u, err := url.Parse(graphBaseURL + path)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("$top", "100")
	if !since.IsZero() {
		q.Set("$filter", fmt.Sprintf("%s ge %s", tsField, since.UTC().Format(time.RFC3339)))
	}
	// $orderby must always be set so pages stream oldest-first; otherwise Graph
	// defaults to descending and a mid-backfill failure persists a cursor at the
	// newest event already seen, causing older un-fetched events to be skipped
	// on retry.
	q.Set("$orderby", tsField+" asc")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

type graphSignInRecord struct {
	ID                string `json:"id"`
	CreatedDateTime   string `json:"createdDateTime"`
	UserID            string `json:"userId"`
	UserPrincipalName string `json:"userPrincipalName"`
	UserDisplayName   string `json:"userDisplayName"`
	AppDisplayName    string `json:"appDisplayName"`
	IPAddress         string `json:"ipAddress"`
	ClientAppUsed     string `json:"clientAppUsed"`
	Status            struct {
		ErrorCode         int    `json:"errorCode"`
		FailureReason     string `json:"failureReason"`
		AdditionalDetails string `json:"additionalDetails"`
	} `json:"status"`
}

func mapGraphSignIn(raw json.RawMessage) (*access.AuditLogEntry, error) {
	var r graphSignInRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	if r.ID == "" {
		return nil, nil
	}
	ts, _ := time.Parse(time.RFC3339, r.CreatedDateTime)
	outcome := "success"
	if r.Status.ErrorCode != 0 || strings.TrimSpace(r.Status.FailureReason) != "" {
		outcome = "failure"
	}
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:         r.ID,
		EventType:       "signIn",
		Action:          "login",
		Timestamp:       ts,
		ActorExternalID: r.UserID,
		ActorEmail:      r.UserPrincipalName,
		IPAddress:       r.IPAddress,
		UserAgent:       r.ClientAppUsed,
		Outcome:         outcome,
		RawData:         rawMap,
	}, nil
}

type graphDirectoryAuditRecord struct {
	ID                  string `json:"id"`
	ActivityDateTime    string `json:"activityDateTime"`
	ActivityDisplayName string `json:"activityDisplayName"`
	Category            string `json:"category"`
	OperationType       string `json:"operationType"`
	Result              string `json:"result"`
	InitiatedBy         struct {
		User struct {
			ID                string `json:"id"`
			UserPrincipalName string `json:"userPrincipalName"`
		} `json:"user"`
	} `json:"initiatedBy"`
	TargetResources []struct {
		ID          string `json:"id"`
		Type        string `json:"type"`
		DisplayName string `json:"displayName"`
	} `json:"targetResources"`
}

func mapGraphDirectoryAudit(raw json.RawMessage) (*access.AuditLogEntry, error) {
	var r graphDirectoryAuditRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	if r.ID == "" {
		return nil, nil
	}
	ts, _ := time.Parse(time.RFC3339, r.ActivityDateTime)
	var targetID, targetType string
	if len(r.TargetResources) > 0 {
		targetID = r.TargetResources[0].ID
		targetType = r.TargetResources[0].Type
	}
	action := strings.ToLower(strings.TrimSpace(r.OperationType))
	if action == "" {
		action = strings.ToLower(strings.TrimSpace(r.ActivityDisplayName))
	}
	rawMap := map[string]interface{}{}
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:          r.ID,
		EventType:        r.Category,
		Action:           action,
		Timestamp:        ts,
		ActorExternalID:  r.InitiatedBy.User.ID,
		ActorEmail:       r.InitiatedBy.User.UserPrincipalName,
		TargetExternalID: targetID,
		TargetType:       targetType,
		Outcome:          normalizeDirectoryAuditOutcome(r.Result),
		RawData:          rawMap,
	}, nil
}

// normalizeDirectoryAuditOutcome maps Microsoft Graph directoryAudit `result`
// values onto the binary success/failure convention used by `mapGraphSignIn`
// and by every other AccessAuditor implementation in this package.
//
// Microsoft's documented enum values are `success`, `failure`, `timeout`, and
// `unknownFutureValue`; downstream audit-pipeline consumers expect only the
// first two. `timeout` and `unknownFutureValue` are surfaced as `failure`
// because neither represents a successful action; an empty `result` falls
// through to `success` to preserve the prior default for events that do not
// report a status (Microsoft Graph returns `result=""` for some legacy
// `directoryAudit` records).
func normalizeDirectoryAuditOutcome(result string) string {
	switch strings.ToLower(strings.TrimSpace(result)) {
	case "success", "":
		return "success"
	default:
		return "failure"
	}
}

var _ access.AccessAuditor = (*M365AccessConnector)(nil)
