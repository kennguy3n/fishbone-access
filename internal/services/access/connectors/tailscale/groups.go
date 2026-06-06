// Package tailscale — GroupSyncer implementation.
//
// Tailscale models groups inside the tailnet ACL document under the
// "groups" key:
//
//   {
//     "groups": {
//       "group:admins":   ["alice@example.com", "bob@example.com"],
//       "group:dev":      ["alice@example.com", "group:admins"]
//     },
//     ...
//   }
//
// The ACL is fetched via GET /api/v2/tailnet/{tailnet}/acl which
// supports Accept: application/json to elide HuJSON comments. Group
// memberships can reference (1) user login names (emails), (2) tag
// names (tag:...), or (3) other group names (group:...). For
// SyncGroupMembers we recursively expand nested group references,
// drop tag references (tags do not correspond to a user record), and
// resolve login names to user.IDs by walking the /users list so the
// emitted memberExternalIDs match the ExternalIDs SyncIdentities
// stores in the registry.
//
// Pagination is N/A — Tailscale returns the entire ACL document in a
// single response and the /users list is unpaginated. Both calls are
// idempotent and safe to retry. The recursive group expansion walks
// at most O(group_count) edges and uses a visited-set to break
// cycles in malformed ACLs.
package tailscale

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type tsACLResponse struct {
	Groups map[string][]string `json:"groups"`
}

// fetchACL returns the parsed groups section of the tailnet ACL.
// Tailscale honours Accept: application/json on the ACL endpoint so
// we receive RFC-8259 JSON (HuJSON comments stripped). Empty groups
// section returns an empty map, not nil, so downstream code can
// range over it unconditionally.
func (c *TailscaleAccessConnector) fetchACL(ctx context.Context, cfg Config, secrets Secrets) (map[string][]string, error) {
	path := "/api/v2/tailnet/" + url.PathEscape(cfg.Tailnet) + "/acl"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
	if err != nil {
		return nil, err
	}
	body, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("tailscale: fetch acl: %w", err)
	}
	var resp tsACLResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("tailscale: decode acl: %w", err)
	}
	if resp.Groups == nil {
		resp.Groups = map[string][]string{}
	}
	return resp.Groups, nil
}

// fetchUserIndex returns a lower-cased loginName → user.ID map so
// SyncGroupMembers can resolve email-style group entries back to
// Tailscale user IDs (which is what SyncIdentities stores as the
// canonical Identity.ExternalID).
func (c *TailscaleAccessConnector) fetchUserIndex(ctx context.Context, cfg Config, secrets Secrets) (map[string]string, error) {
	req, err := c.newRequest(ctx, secrets, http.MethodGet, "/api/v2/tailnet/"+url.PathEscape(cfg.Tailnet)+"/users")
	if err != nil {
		return nil, err
	}
	body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var resp tsUsersResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("tailscale: decode users: %w", err)
	}
	index := make(map[string]string, len(resp.Users))
	for _, u := range resp.Users {
		login := strings.ToLower(strings.TrimSpace(u.LoginName))
		if login == "" || u.ID == "" {
			continue
		}
		index[login] = u.ID
	}
	return index, nil
}

// CountGroups returns the count of groups defined in the tailnet ACL.
func (c *TailscaleAccessConnector) CountGroups(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	groups, err := c.fetchACL(ctx, cfg, secrets)
	if err != nil {
		return 0, err
	}
	return len(groups), nil
}

// SyncGroups emits one Identity per group defined in the tailnet ACL.
// ExternalID is the fully-qualified group name (e.g. "group:admins")
// so SyncGroupMembers can resolve back to the same ACL entry.
func (c *TailscaleAccessConnector) SyncGroups(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	_ string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	groups, err := c.fetchACL(ctx, cfg, secrets)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	identities := make([]*access.Identity, 0, len(names))
	for _, name := range names {
		identities = append(identities, &access.Identity{
			ExternalID:  name,
			Type:        access.IdentityTypeGroup,
			DisplayName: name,
			Status:      "active",
		})
	}
	return handler(identities, "")
}

// SyncGroupMembers recursively expands the ACL group named
// groupExternalID, dropping tag references and resolving login-name
// references to Tailscale user IDs via the /users index. Cycles in
// the ACL are broken by a visited-set; missing nested groups are
// silently skipped (they are an ACL configuration error, not a sync
// error). The handler receives memberExternalIDs that match
// SyncIdentities' u.ID convention so the registry can stitch.
func (c *TailscaleAccessConnector) SyncGroupMembers(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	groupExternalID, _ string,
	handler func(memberExternalIDs []string, nextCheckpoint string) error,
) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	groupName := strings.TrimSpace(groupExternalID)
	if groupName == "" {
		return fmt.Errorf("tailscale: sync group members: groupExternalID is required")
	}
	groups, err := c.fetchACL(ctx, cfg, secrets)
	if err != nil {
		return err
	}
	if _, ok := groups[groupName]; !ok {
		// Group no longer exists in the ACL — emit empty membership
		// (handler still invoked so the registry can recognise the
		// group is empty rather than skipping due to error).
		// Non-nil empty slice per GroupSyncer empty-batch contract —
		// see optional_interfaces.go.
		return handler([]string{}, "")
	}
	users, err := c.fetchUserIndex(ctx, cfg, secrets)
	if err != nil {
		return err
	}
	visited := map[string]bool{}
	memberIDs := map[string]struct{}{}
	c.expandGroup(groupName, groups, users, visited, memberIDs)
	out := make([]string, 0, len(memberIDs))
	for id := range memberIDs {
		out = append(out, id)
	}
	sort.Strings(out)
	return handler(out, "")
}

// expandGroup recursively resolves the group's membership list,
// inlining nested group references and dropping tags. visited
// tracks the set of group names already walked so a cycle in the
// ACL terminates rather than infinite-looping.
func (c *TailscaleAccessConnector) expandGroup(
	name string,
	groups map[string][]string,
	users map[string]string,
	visited map[string]bool,
	out map[string]struct{},
) {
	if visited[name] {
		return
	}
	visited[name] = true
	for _, m := range groups[name] {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		switch {
		case strings.HasPrefix(m, "group:"):
			c.expandGroup(m, groups, users, visited, out)
		case strings.HasPrefix(m, "tag:"):
			// Tags don't correspond to a user record — skip.
			continue
		default:
			if id, ok := users[strings.ToLower(m)]; ok {
				out[id] = struct{}{}
			}
		}
	}
}

var _ access.GroupSyncer = (*TailscaleAccessConnector)(nil)
