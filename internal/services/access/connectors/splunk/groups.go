// Package splunk — GroupSyncer over the Splunk roles + users API.
//
// Splunk models access groups as "roles". The REST API exposes:
//
//	GET /services/authorization/roles?output_mode=json&count=...&offset=...
//	GET /services/authentication/users?output_mode=json&count=...&offset=...
//
// Each role's response contains its name + capabilities array but
// not its members. Each user's response contains a `roles` array of
// role names. Membership is therefore derived by walking every user
// and emitting users whose `roles` array contains the requested
// role name. This is the documented mechanism — Splunk has no
// inverse "members of a role" endpoint — and the cost is O(N_users)
// per role-sync, identical to what the upstream forces every other
// SIEM operator to do.
package splunk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// splunkGroupsMaxPages caps the per-call page walk in CountGroups /
// SyncGroups / SyncGroupMembers. Even with an aggressively oversized
// Splunk org (10k+ roles or 100k+ users at pageSize=100), legitimate
// pagination terminates well below this bound. The cap is a
// defense-in-depth guard against a misconfigured / malicious upstream
// returning a perpetually inflated paging.Total combined with a
// non-empty page on every request — the secondary empty-page guard
// would not catch that. Mirrors splunkAuditMaxPages=200 in audit.go.
const splunkGroupsMaxPages = 2000

type splunkRoleEntry struct {
	Name    string `json:"name"`
	Content struct {
		Capabilities       []string `json:"capabilities"`
		ImportedCapas      []string `json:"imported_capabilities"`
		ImportedRoles      []string `json:"imported_roles"`
		DefaultApp         string   `json:"defaultApp"`
		SrchIndexesAllowed []string `json:"srchIndexesAllowed"`
	} `json:"content"`
}

type splunkRolesResponse struct {
	Entry  []splunkRoleEntry `json:"entry"`
	Paging struct {
		Total   int `json:"total"`
		PerPage int `json:"perPage"`
		Offset  int `json:"offset"`
	} `json:"paging"`
}

type splunkUserWithRoles struct {
	Name    string `json:"name"`
	Content struct {
		Email    string   `json:"email"`
		RealName string   `json:"realname"`
		Roles    []string `json:"roles"`
	} `json:"content"`
}

type splunkUsersWithRolesResponse struct {
	Entry  []splunkUserWithRoles `json:"entry"`
	Paging struct {
		Total   int `json:"total"`
		PerPage int `json:"perPage"`
		Offset  int `json:"offset"`
	} `json:"paging"`
}

// CountGroups walks every page of /services/authorization/roles and
// returns the cumulative role count. The first page surfaces
// paging.total but we walk anyway for parity with the audit-log
// "trust the actual data" rule.
func (c *SplunkAccessConnector) CountGroups(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	base := c.baseURL(cfg)
	offset := 0
	total := 0
	for pages := 0; pages < splunkGroupsMaxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		path := fmt.Sprintf("%s/services/authorization/roles?output_mode=json&count=%d&offset=%d", base, pageSize, offset)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return 0, err
		}
		body, err := c.do(req)
		if err != nil {
			return 0, err
		}
		var page splunkRolesResponse
		if err := json.Unmarshal(body, &page); err != nil {
			return 0, fmt.Errorf("splunk: decode roles: %w", err)
		}
		total += len(page.Entry)
		if len(page.Entry) == 0 || offset+len(page.Entry) >= page.Paging.Total {
			return total, nil
		}
		offset += pageSize
	}
	return total, fmt.Errorf("splunk: count groups: pagination exceeded %d pages (server returned non-terminating paging.total)", splunkGroupsMaxPages)
}

// SyncGroups paginates /services/authorization/roles via the
// count + offset query parameters. ExternalID is the role name
// (Splunk's stable role identifier).
func (c *SplunkAccessConnector) SyncGroups(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	offset := 0
	if checkpoint != "" {
		_, _ = fmt.Sscanf(checkpoint, "%d", &offset)
		if offset < 0 {
			offset = 0
		}
	}
	base := c.baseURL(cfg)
	for pages := 0; pages < splunkGroupsMaxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		path := fmt.Sprintf("%s/services/authorization/roles?output_mode=json&count=%d&offset=%d", base, pageSize, offset)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var page splunkRolesResponse
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("splunk: decode roles: %w", err)
		}
		identities := make([]*access.Identity, 0, len(page.Entry))
		for _, e := range page.Entry {
			identities = append(identities, &access.Identity{
				ExternalID:  e.Name,
				Type:        access.IdentityTypeGroup,
				DisplayName: e.Name,
				Status:      "active",
				RawData: map[string]interface{}{
					"capabilities":          e.Content.Capabilities,
					"imported_capabilities": e.Content.ImportedCapas,
					"imported_roles":        e.Content.ImportedRoles,
				},
			})
		}
		next := ""
		if offset+len(page.Entry) < page.Paging.Total && len(page.Entry) > 0 {
			next = fmt.Sprintf("%d", offset+pageSize)
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		offset += pageSize
	}
	return fmt.Errorf("splunk: sync groups: pagination exceeded %d pages (server returned non-terminating paging.total)", splunkGroupsMaxPages)
}

// SyncGroupMembers walks every page of /services/authentication/users
// and emits the user name for every user whose `content.roles` array
// contains the requested role. Splunk does not expose an inverse
// "members of a role" endpoint, so this user-walk is the documented
// mechanism. The handler is invoked per page of users (not per
// chunk of matching members) so the caller can checkpoint mid-walk
// on the user-pagination offset.
func (c *SplunkAccessConnector) SyncGroupMembers(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	groupExternalID, checkpoint string,
	handler func(memberExternalIDs []string, nextCheckpoint string) error,
) error {
	groupExternalID = strings.TrimSpace(groupExternalID)
	if groupExternalID == "" {
		return errors.New("splunk: sync group members: groupExternalID is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	offset := 0
	if checkpoint != "" {
		_, _ = fmt.Sscanf(checkpoint, "%d", &offset)
		if offset < 0 {
			offset = 0
		}
	}
	base := c.baseURL(cfg)
	for pages := 0; pages < splunkGroupsMaxPages; pages++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		path := fmt.Sprintf("%s/services/authentication/users?output_mode=json&count=%d&offset=%d", base, pageSize, offset)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var page splunkUsersWithRolesResponse
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("splunk: decode users: %w", err)
		}
		matched := make([]string, 0, len(page.Entry))
		for _, u := range page.Entry {
			for _, r := range u.Content.Roles {
				if r == groupExternalID {
					matched = append(matched, u.Name)
					break
				}
			}
		}
		next := ""
		if offset+len(page.Entry) < page.Paging.Total && len(page.Entry) > 0 {
			next = fmt.Sprintf("%d", offset+pageSize)
		}
		if err := handler(matched, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		offset += pageSize
	}
	return fmt.Errorf("splunk: sync group members: pagination exceeded %d pages (server returned non-terminating paging.total)", splunkGroupsMaxPages)
}

var _ access.GroupSyncer = (*SplunkAccessConnector)(nil)
