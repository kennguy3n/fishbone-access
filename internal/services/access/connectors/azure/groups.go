// Package azure — GroupSyncer implementation over Microsoft Graph.
//
// Entra ID models user collections as Microsoft 365 / security
// Groups under `/groups`. The connector enumerates them via the
// standard paginated Graph endpoints:
//
//	GET /groups?$select=id,displayName,description,securityEnabled,mailEnabled
//	GET /groups/{id}/members?$select=id,@odata.type
//	GET /groups/$count (ConsistencyLevel: eventual)
//
// All three reuse the existing graphClient + doJSON helpers from
// connector.go which already inject the OAuth bearer token and
// `ConsistencyLevel: eventual` headers required by Graph for
// $count and advanced queries.
package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

type azureGroup struct {
	ID              string `json:"id"`
	DisplayName     string `json:"displayName"`
	Description     string `json:"description"`
	SecurityEnabled bool   `json:"securityEnabled"`
	MailEnabled     bool   `json:"mailEnabled"`
	Mail            string `json:"mail"`
}

type azureGroupsResponse struct {
	NextLink string       `json:"@odata.nextLink,omitempty"`
	Value    []azureGroup `json:"value"`
}

type azureMember struct {
	ID                string `json:"id"`
	OdataType         string `json:"@odata.type"`
	UserPrincipalName string `json:"userPrincipalName,omitempty"`
}

type azureMembersResponse struct {
	NextLink string        `json:"@odata.nextLink,omitempty"`
	Value    []azureMember `json:"value"`
}

// CountGroups uses GET /groups/$count which returns a plain integer
// body. Requires ConsistencyLevel: eventual (set by doJSON for all
// Graph requests).
func (c *AzureAccessConnector) CountGroups(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	client := c.graphClient(ctx, cfg, secrets)
	body, err := c.doJSON(ctx, client, http.MethodGet, "/groups/$count")
	if err != nil {
		return 0, err
	}
	var n int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(body)), "%d", &n); err != nil {
		return 0, fmt.Errorf("azure: parse group count: %w", err)
	}
	return n, nil
}

// SyncGroups paginates GET /groups via @odata.nextLink. Each Identity
// is type IdentityTypeGroup with ExternalID set to the immutable
// Entra ID directory object id. The checkpoint format is the relative
// nextLink (consistent with SyncIdentities), so resuming after a
// crash continues from the exact next page.
func (c *AzureAccessConnector) SyncGroups(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	client := c.graphClient(ctx, cfg, secrets)
	path := "/groups?$select=id,displayName,description,securityEnabled,mailEnabled,mail&$top=200"
	if checkpoint != "" {
		path = checkpoint
	}
	for page := 0; page < azureSyncMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		body, err := c.doJSON(ctx, client, http.MethodGet, path)
		if err != nil {
			return err
		}
		var resp azureGroupsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("azure: decode groups: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Value))
		for _, g := range resp.Value {
			display := g.DisplayName
			if display == "" {
				display = g.ID
			}
			identities = append(identities, &access.Identity{
				ExternalID:  g.ID,
				Type:        access.IdentityTypeGroup,
				DisplayName: display,
				Email:       g.Mail,
				Status:      "active",
				RawData: map[string]interface{}{
					"description":      g.Description,
					"security_enabled": g.SecurityEnabled,
					"mail_enabled":     g.MailEnabled,
				},
			})
		}
		// Follow @odata.nextLink verbatim; doJSON resolves absolute
		// URLs directly (see SyncIdentities for rationale).
		next := resp.NextLink
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		path = next
	}
	// Hit the defensive page cap; the last handler call carried a
	// non-empty checkpoint, so the next sync cycle resumes from there.
	return nil
}

// SyncGroupMembers paginates GET /groups/{id}/members and emits the
// directory object id of every member. Members can be users, groups,
// or service principals — we surface all of them and let the caller
// classify by @odata.type via downstream identity lookup; the
// SyncGroupMembers contract is "external IDs of members", not "users
// only".
func (c *AzureAccessConnector) SyncGroupMembers(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	groupExternalID, checkpoint string,
	handler func(memberExternalIDs []string, nextCheckpoint string) error,
) error {
	if strings.TrimSpace(groupExternalID) == "" {
		return errors.New("azure: group external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	client := c.graphClient(ctx, cfg, secrets)
	path := "/groups/" + url.PathEscape(groupExternalID) + "/members?$select=id,userPrincipalName&$top=200"
	if checkpoint != "" {
		path = checkpoint
	}
	for page := 0; page < azureSyncMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		body, err := c.doJSON(ctx, client, http.MethodGet, path)
		if err != nil {
			return err
		}
		var resp azureMembersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("azure: decode group members: %w", err)
		}
		memberIDs := make([]string, 0, len(resp.Value))
		for _, m := range resp.Value {
			if m.ID != "" {
				memberIDs = append(memberIDs, m.ID)
			}
		}
		// Follow @odata.nextLink verbatim; doJSON resolves absolute
		// URLs directly (see SyncIdentities for rationale).
		next := resp.NextLink
		if err := handler(memberIDs, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		path = next
	}
	// Hit the defensive page cap; the last handler call carried a
	// non-empty checkpoint, so the next sync cycle resumes from there.
	return nil
}

var _ access.GroupSyncer = (*AzureAccessConnector)(nil)
