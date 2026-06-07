// Package gitlab — SCIM v2.0 outbound provisioning composition.
//
// GitLab exposes Group SAML SSO + SCIM 2.0 for paid groups on
// GitLab.com and self-managed Premium+. The SCIM endpoints live at:
//
//	{base}/api/scim/v2/groups/{group_path}/Users
//	{base}/api/scim/v2/groups/{group_path}/Groups
//
// per https://docs.gitlab.com/ee/api/scim.html. Authentication uses
// the same `Bearer {access_token}` model as the rest of the GitLab
// API: a Group SAML SSO administrator generates a SCIM-scoped
// token from the group's SAML SSO settings page. The token may be
// distinct from the access_token used for the broader connector
// surface (e.g., the operator might rotate the SCIM token
// independently for least-privilege provisioning) — surfaced as
// the optional `scim_token` secret, falling back to `access_token`
// when not set so existing operators don't need a config change.
package gitlab

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

var (
	scimClientOnce sync.Once
	scimClient     *access.SCIMClient
)

func scim() *access.SCIMClient {
	scimClientOnce.Do(func() {
		scimClient = access.NewSCIMClient()
	})
	return scimClient
}

// SetSCIMClientForTest swaps the package-level SCIMClient and
// returns the previous one so tests can restore it on cleanup.
func SetSCIMClientForTest(c *access.SCIMClient) *access.SCIMClient {
	prev := scim()
	scimClient = c
	return prev
}

// scimConfig adapts the GitLab connector's config + secrets into
// the shared SCIMClient's `scim_base_url` + `scim_auth_header`
// pair. The SCIM endpoint is rooted at
// `{base}/api/scim/v2/groups/{group_path}`; group_path is the URL
// path of the top-level group that owns SAML SSO (e.g.,
// "acme-corp"). Note that GitLab's /api/scim/v2/groups endpoint
// requires the URL-encoded *path* of the group, NOT its numeric ID
// — passing a numeric `group_id` here produces a 404. When the
// operator only supplies a numeric `group_id` we surface a clear
// configuration error directing them to set `group_path`
// explicitly. When `scim_token` is unset we fall back to
// `access_token` because the same PAT/Group access token can carry
// SCIM scope when minted with the `scim_oauth2` scope set.
func (c *GitLabAccessConnector) scimConfig(configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, nil, err
	}
	var groupPath string
	if v, ok := configRaw["group_path"].(string); ok {
		groupPath = strings.TrimSpace(v)
	}
	if groupPath == "" {
		groupPath = strings.TrimSpace(cfg.GroupID)
		if groupPath != "" && isNumericGroupRef(groupPath) {
			return nil, nil, fmt.Errorf("gitlab: group_path is required for SCIM (configured group_id %q is numeric; "+
				"GitLab's /api/scim/v2/groups endpoint requires the URL-encoded group path, e.g. \"acme-corp\")", groupPath)
		}
	}
	groupPath = strings.Trim(groupPath, "/")
	if groupPath == "" {
		return nil, nil, errors.New("gitlab: group_id (or group_path) is required for SCIM")
	}
	token := strings.TrimSpace(secrets.AccessToken)
	if v, ok := secretsRaw["scim_token"].(string); ok {
		if s := strings.TrimSpace(v); s != "" {
			token = s
		}
	}
	if token == "" {
		return nil, nil, errors.New("gitlab: scim_token (or access_token) is required for SCIM provisioning")
	}
	// groupPath may contain forward slashes for nested groups
	// (e.g. "acme/devops"). The SCIM endpoint requires the full
	// nested path URL-encoded as a single path segment — i.e. the
	// internal slashes must be escaped to %2F. url.PathEscape does
	// exactly that. Every other URL builder in this package already
	// does this for cfg.GroupID; the SCIM builder was the lone
	// exception.
	base := c.baseURL(cfg) + "/api/scim/v2/groups/" + url.PathEscape(groupPath)
	return map[string]interface{}{
			"scim_base_url": base,
		}, map[string]interface{}{
			"scim_auth_header": "Bearer " + strings.TrimPrefix(token, "Bearer "),
		}, nil
}

// PushSCIMUser satisfies access.SCIMProvisioner.
func (c *GitLabAccessConnector) PushSCIMUser(ctx context.Context, configRaw, secretsRaw map[string]interface{}, user access.SCIMUser) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMUser(ctx, scimCfg, scimSecrets, user)
}

// PushSCIMGroup satisfies access.SCIMProvisioner.
func (c *GitLabAccessConnector) PushSCIMGroup(ctx context.Context, configRaw, secretsRaw map[string]interface{}, group access.SCIMGroup) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().PushSCIMGroup(ctx, scimCfg, scimSecrets, group)
}

// DeleteSCIMResource satisfies access.SCIMProvisioner.
func (c *GitLabAccessConnector) DeleteSCIMResource(ctx context.Context, configRaw, secretsRaw map[string]interface{}, resourceType, externalID string) error {
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	return scim().DeleteSCIMResource(ctx, scimCfg, scimSecrets, resourceType, externalID)
}

var _ access.SCIMProvisioner = (*GitLabAccessConnector)(nil)

// isNumericGroupRef reports whether s consists entirely of ASCII
// digits, indicating the operator supplied GitLab's opaque numeric
// group ID rather than the URL-encoded group path that the SCIM
// endpoint requires.
func isNumericGroupRef(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
