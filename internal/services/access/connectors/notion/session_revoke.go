package notion

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// scimPatchOp is the RFC 7644 §3.5.2 PatchOp envelope. Notion's
// enterprise SCIM endpoint accepts a "replace" of the `active`
// attribute to deactivate (and thereby deprovision) a user.
type scimPatchOp struct {
	Schemas    []string             `json:"schemas"`
	Operations []scimPatchOperation `json:"Operations"`
}

type scimPatchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value"`
}

// RevokeUserSessions implements access.SessionRevoker for Notion.
//
// Notion's PUBLIC v1 API exposes no user-mutation or per-user logout
// endpoint — the /v1/users/* routes are read-only (GET retrieve/list
// only), so a PATCH there 404s and the kill switch silently no-ops.
// The supported deprovisioning surface is the enterprise SCIM 2.0
// endpoint at {base}/scim/v2/Users/{id}: a PatchOp setting
// `active:false` deactivates the user, which the workspace translates
// into an invalidation of every active browser / desktop / mobile
// session for that principal. The next sign-in must round-trip the
// federated IdP.
//
// userExternalID is the Notion user ID (the same value SyncIdentities
// emits as Identity.ExternalID, and the SCIM resource id). 2xx means
// propagated; 404 means the user is already gone and is treated as
// success (idempotent kill switch per docs/architecture.md §2). Any
// other status returns a non-nil err so the leaver flow logs it but
// continues to the next kill-switch layer.
func (c *NotionAccessConnector) RevokeUserSessions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) error {
	if strings.TrimSpace(userExternalID) == "" {
		return fmt.Errorf("notion: session revoke: userExternalID is required")
	}
	// scimConfig is the single source of truth for the SCIM base URL
	// (baseURL()+"/scim/v2") and the bearer auth header, shared with
	// PushSCIMUser / DeleteSCIMResource.
	scimCfg, scimSecrets, err := c.scimConfig(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	base, _ := scimCfg["scim_base_url"].(string)
	authHeader, _ := scimSecrets["scim_auth_header"].(string)

	payload, err := json.Marshal(scimPatchOp{
		Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		Operations: []scimPatchOperation{
			{Op: "replace", Path: "active", Value: false},
		},
	})
	if err != nil {
		return fmt.Errorf("notion: session revoke: marshal payload: %w", err)
	}
	endpoint := strings.TrimRight(base, "/") + "/Users/" + url.PathEscape(userExternalID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/scim+json")
	req.Header.Set("Content-Type", "application/scim+json")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("notion: session revoke: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	// A 404 means the SCIM User record is already gone, which is a
	// successful end state for an idempotent kill switch.
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	return fmt.Errorf("notion: session revoke status %d: %s", resp.StatusCode, string(body))
}
