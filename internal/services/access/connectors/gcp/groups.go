// Package gcp — GroupSyncer implementation over Cloud Identity v1.
//
// Cloud Identity Groups model security / mailing groups at the
// customer (= GCP org / Workspace customer) level, separate from
// project-scoped IAM bindings. Group resource names follow the
// `groups/{id}` format and members are addressed by membership name
// `groups/{id}/memberships/{member_id}`.
//
//   GET  /v1/groups?parent=customers/{customerId}&pageSize=...
//   GET  /v1/{groupName}/memberships?pageSize=...
//
// The connector reads Config.CustomerID (a top-level customer
// resource id, e.g. "C0123abcd" or "my_customer") and routes via the
// `cloudidentity.googleapis.com` host. Tests override the host via
// urlOverride which is shared with the Cloud Resource Manager
// plumbing so a single httptest server can serve every API.
package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

const cloudIdentityDefaultHost = "https://cloudidentity.googleapis.com"

// cloudIdentityHost returns the host used for Cloud Identity API
// calls. In tests urlOverride is non-empty and points at the
// httptest server; in production the upstream public host is
// returned. The connector tolerates a trailing slash on urlOverride.
func (c *GCPAccessConnector) cloudIdentityHost() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return cloudIdentityDefaultHost
}

// customerID returns the Cloud Identity customer resource that
// scopes the groups listing. SyncGroups requires this to be
// non-empty.
func (c *GCPAccessConnector) customerID(cfg Config) string {
	v := strings.TrimSpace(cfg.CustomerID)
	if v == "" {
		return ""
	}
	if !strings.HasPrefix(v, "customers/") {
		v = "customers/" + v
	}
	return v
}

type cloudIdentityGroup struct {
	Name        string            `json:"name"` // groups/{id}
	GroupKey    cloudIdentityKey  `json:"groupKey"`
	DisplayName string            `json:"displayName"`
	Description string            `json:"description"`
	Labels      map[string]string `json:"labels"`
}

type cloudIdentityKey struct {
	ID        string `json:"id"`
	Namespace string `json:"namespace,omitempty"`
}

type cloudIdentityGroupsResponse struct {
	Groups        []cloudIdentityGroup `json:"groups"`
	NextPageToken string               `json:"nextPageToken,omitempty"`
}

type cloudIdentityMember struct {
	Name             string           `json:"name"` // groups/{g}/memberships/{m}
	PreferredMemberKey cloudIdentityKey `json:"preferredMemberKey"`
	Type             string           `json:"type"`
}

type cloudIdentityMembersResponse struct {
	Memberships   []cloudIdentityMember `json:"memberships"`
	NextPageToken string                `json:"nextPageToken,omitempty"`
}

// requestCloudIdentity performs a GET against the Cloud Identity
// host and returns the decoded body. 5xx and 4xx surface as errors
// with the upstream body verbatim so the caller can match on
// reason codes.
func (c *GCPAccessConnector) requestCloudIdentity(ctx context.Context, client httpDoer, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cloudIdentityHost()+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gcp: cloudidentity %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("gcp: cloudidentity %s: status %d: %s", path, resp.StatusCode, string(body))
	}
	return body, nil
}

// CountGroups walks every page of /v1/groups under the configured
// customer. Cloud Identity does not expose a /count endpoint, so
// the count is derived from a full enumeration.
func (c *GCPAccessConnector) CountGroups(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	parent := c.customerID(cfg)
	if parent == "" {
		return 0, errors.New("gcp: count groups: customer_id is required")
	}
	client, err := c.cloudIdentityClient(ctx, cfg, secrets)
	if err != nil {
		return 0, err
	}
	total := 0
	pageToken := ""
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		q := url.Values{}
		q.Set("parent", parent)
		q.Set("pageSize", "200")
		if pageToken != "" {
			q.Set("pageToken", pageToken)
		}
		body, err := c.requestCloudIdentity(ctx, client, "/v1/groups?"+q.Encode())
		if err != nil {
			return 0, err
		}
		var resp cloudIdentityGroupsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return 0, fmt.Errorf("gcp: decode groups: %w", err)
		}
		total += len(resp.Groups)
		if resp.NextPageToken == "" {
			return total, nil
		}
		pageToken = resp.NextPageToken
	}
}

// SyncGroups paginates /v1/groups via nextPageToken. ExternalID is
// the Cloud Identity resource name (`groups/{id}`) which is the
// stable identifier; DisplayName falls back to groupKey.id when the
// optional displayName is unset. The checkpoint format is the raw
// nextPageToken so resume-from-crash continues from the next
// upstream page.
func (c *GCPAccessConnector) SyncGroups(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	parent := c.customerID(cfg)
	if parent == "" {
		return errors.New("gcp: sync groups: customer_id is required")
	}
	client, err := c.cloudIdentityClient(ctx, cfg, secrets)
	if err != nil {
		return err
	}
	pageToken := checkpoint
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("parent", parent)
		q.Set("pageSize", "200")
		if pageToken != "" {
			q.Set("pageToken", pageToken)
		}
		body, err := c.requestCloudIdentity(ctx, client, "/v1/groups?"+q.Encode())
		if err != nil {
			return err
		}
		var resp cloudIdentityGroupsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("gcp: decode groups: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Groups))
		for _, g := range resp.Groups {
			display := g.DisplayName
			if display == "" {
				display = g.GroupKey.ID
			}
			identities = append(identities, &access.Identity{
				ExternalID:  g.Name,
				Type:        access.IdentityTypeGroup,
				DisplayName: display,
				Email:       g.GroupKey.ID,
				Status:      "active",
				RawData: map[string]interface{}{
					"description": g.Description,
					"labels":      g.Labels,
				},
			})
		}
		if err := handler(identities, resp.NextPageToken); err != nil {
			return err
		}
		if resp.NextPageToken == "" {
			return nil
		}
		pageToken = resp.NextPageToken
	}
}

// SyncGroupMembers paginates /v1/{group}/memberships via
// nextPageToken. groupExternalID is the Cloud Identity resource
// name (`groups/{id}`) — exactly the form emitted by SyncGroups.
// Members surface as `preferredMemberKey.id` which is the upstream
// principal identifier (typically an email address). Group-of-group
// memberships are passed through verbatim; the caller classifies
// via downstream identity lookup.
func (c *GCPAccessConnector) SyncGroupMembers(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	groupExternalID, checkpoint string,
	handler func(memberExternalIDs []string, nextCheckpoint string) error,
) error {
	groupExternalID = strings.TrimSpace(groupExternalID)
	if groupExternalID == "" {
		return errors.New("gcp: sync group members: groupExternalID is required")
	}
	if !strings.HasPrefix(groupExternalID, "groups/") {
		groupExternalID = "groups/" + groupExternalID
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	client, err := c.cloudIdentityClient(ctx, cfg, secrets)
	if err != nil {
		return err
	}
	// `groupExternalID` is part of the path; escape each segment but keep `/`.
	parts := strings.Split(groupExternalID, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	groupPath := strings.Join(parts, "/")
	pageToken := checkpoint
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("pageSize", "200")
		if pageToken != "" {
			q.Set("pageToken", pageToken)
		}
		body, err := c.requestCloudIdentity(ctx, client, "/v1/"+groupPath+"/memberships?"+q.Encode())
		if err != nil {
			return err
		}
		var resp cloudIdentityMembersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("gcp: decode group members: %w", err)
		}
		ids := make([]string, 0, len(resp.Memberships))
		for _, m := range resp.Memberships {
			if m.PreferredMemberKey.ID != "" {
				ids = append(ids, m.PreferredMemberKey.ID)
			}
		}
		if err := handler(ids, resp.NextPageToken); err != nil {
			return err
		}
		if resp.NextPageToken == "" {
			return nil
		}
		pageToken = resp.NextPageToken
	}
}

var _ access.GroupSyncer = (*GCPAccessConnector)(nil)
