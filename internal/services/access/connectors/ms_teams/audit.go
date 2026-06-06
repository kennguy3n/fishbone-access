package msteams

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

// MS Teams audit partition key. The MS Teams connector reuses Microsoft
// Graph's `/auditLogs/signIns` endpoint, filtered for Teams events; the
// worker tracks an independent cursor per partition so a fast-moving
// signIns stream never shadows a slower partition's progress on retry.
const auditPartitionTeamsSignIns = "ms_teams/signIns"

// teamsAuditMaxPages bounds signIns pagination so a misbehaving or compromised
// endpoint that keeps returning @odata.nextLink cannot loop indefinitely,
// matching the 200-page cap used by every other audit connector.
const teamsAuditMaxPages = 200

// FetchAccessAuditLogs streams Microsoft Teams sign-in events from
// Microsoft Graph back into the access audit pipeline. Implements
// access.AccessAuditor.
//
// Endpoint:
//
//	GET /auditLogs/signIns?$filter=createdDateTime ge {since}
//	    and appDisplayName eq 'Microsoft Teams'
//
// Pagination uses `@odata.nextLink`. The handler is invoked once per
// page in chronological order; the partition key is "ms_teams/signIns"
// so the worker can advance the cursor independently of the parent
// `microsoft` connector's partitions.
func (c *MSTeamsAccessConnector) FetchAccessAuditLogs(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	sincePartitions map[string]time.Time,
	handler func(batch []*access.AuditLogEntry, nextSince time.Time, partitionKey string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	client := c.graphClient(ctx, cfg, secrets)
	since := sincePartitions[auditPartitionTeamsSignIns]
	cursor := since
	next, err := buildTeamsAuditStartURL(c.baseURL(), since)
	if err != nil {
		return err
	}
	for pages := 0; next != "" && pages < teamsAuditMaxPages; pages++ {
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
			return fmt.Errorf("ms_teams: audit signIns: %w", err)
		}
		body, readErr := readResponse(resp)
		if readErr != nil {
			return readErr
		}
		// Tenants on plans that do not include sign-in audit logs (e.g.
		// non-AAD-Premium) get a 403; collapse to ErrAuditNotAvailable.
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
			return access.ErrAuditNotAvailable
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("ms_teams: audit signIns: status %d: %s", resp.StatusCode, string(body))
		}
		var page struct {
			Value    []teamsSignInRecord `json:"value"`
			NextLink string              `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("ms_teams: decode signIns page: %w", err)
		}
		batch := make([]*access.AuditLogEntry, 0, len(page.Value))
		batchMax := cursor
		for i := range page.Value {
			entry := mapTeamsSignIn(&page.Value[i])
			if entry == nil {
				continue
			}
			if entry.Timestamp.After(batchMax) {
				batchMax = entry.Timestamp
			}
			batch = append(batch, entry)
		}
		if err := handler(batch, batchMax, auditPartitionTeamsSignIns); err != nil {
			return err
		}
		cursor = batchMax
		nl := strings.TrimSpace(page.NextLink)
		if nl == "" {
			return nil
		}
		// Rewrite absolute next-links to urlOverride for tests.
		if c.urlOverride != "" && strings.HasPrefix(nl, defaultBaseURL) {
			nl = strings.Replace(nl, defaultBaseURL, strings.TrimRight(c.urlOverride, "/"), 1)
		}
		next = nl
	}
	return nil
}

func buildTeamsAuditStartURL(base string, since time.Time) (string, error) {
	u, err := url.Parse(strings.TrimRight(base, "/") + "/auditLogs/signIns")
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("$top", "100")
	q.Set("$orderby", "createdDateTime asc")
	filter := "appDisplayName eq 'Microsoft Teams'"
	if !since.IsZero() {
		filter = fmt.Sprintf("createdDateTime ge %s and %s", since.UTC().Format(time.RFC3339), filter)
	}
	q.Set("$filter", filter)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

type teamsSignInRecord struct {
	ID                string `json:"id"`
	CreatedDateTime   string `json:"createdDateTime"`
	UserID            string `json:"userId"`
	UserPrincipalName string `json:"userPrincipalName"`
	UserDisplayName   string `json:"userDisplayName"`
	AppDisplayName    string `json:"appDisplayName"`
	IPAddress         string `json:"ipAddress"`
	ClientAppUsed     string `json:"clientAppUsed"`
	Status            struct {
		ErrorCode     int    `json:"errorCode"`
		FailureReason string `json:"failureReason"`
	} `json:"status"`
}

func mapTeamsSignIn(r *teamsSignInRecord) *access.AuditLogEntry {
	if r == nil || strings.TrimSpace(r.ID) == "" {
		return nil
	}
	ts := parseTeamsTime(r.CreatedDateTime)
	if ts.IsZero() {
		return nil
	}
	outcome := "success"
	if r.Status.ErrorCode != 0 || strings.TrimSpace(r.Status.FailureReason) != "" {
		outcome = "failure"
	}
	rawMap := map[string]interface{}{}
	raw, _ := json.Marshal(r)
	_ = json.Unmarshal(raw, &rawMap)
	return &access.AuditLogEntry{
		EventID:         r.ID,
		EventType:       "signIn",
		Action:          "login",
		Timestamp:       ts,
		ActorExternalID: strings.TrimSpace(r.UserID),
		ActorEmail:      strings.TrimSpace(r.UserPrincipalName),
		IPAddress:       strings.TrimSpace(r.IPAddress),
		UserAgent:       strings.TrimSpace(r.ClientAppUsed),
		Outcome:         outcome,
		RawData:         rawMap,
	}
}

// parseTeamsTime parses Microsoft Graph's RFC3339-nano timestamps with a
// fall back to plain RFC3339 for legacy payloads.
func parseTeamsTime(s string) time.Time {
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

func readResponse(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	const max = 1 << 20
	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if len(buf) >= max {
				break
			}
		}
		if err != nil {
			break
		}
	}
	return buf, nil
}

var _ access.AccessAuditor = (*MSTeamsAccessConnector)(nil)
