// Package gcp — SessionRevoker via service-account key disable.
//
// GCP does not expose a session-revocation API for human IAM
// principals: leaver flows for human users are expected to run
// against the upstream identity provider (Google Workspace, an
// external SAML IdP, or the Workforce Identity Federation pool) via
// the dedicated google_workspace / IdP connectors.
//
// What GCP DOES expose, and what this implementation covers, is
// disabling service-account keys — the long-lived JSON credentials
// that automation pipelines and on-prem agents use to authenticate
// as a service account. Disabling every key for a service account
// is the GCP-side kill switch for that principal because:
//
//  1. New OAuth 2.0 access tokens cannot be minted from a disabled
//     key (iam.googleapis.com/v1/{key}:disable returns 200 and the
//     key transitions to DISABLED).
//  2. Existing access tokens minted from those keys remain valid
//     until they expire (typically <= 1 hour) — the same trade-off
//     every cloud-vendor session-kill API makes.
//
// The userExternalID input is the service account email
// (e.g. "ci-runner@my-project.iam.gserviceaccount.com"). A
// `serviceAccount:` IAM-policy prefix is tolerated and stripped.
// Human user IDs (those starting with `user:`) are rejected with an
// explicit error pointing the operator at the google_workspace
// connector — silently no-op-ing would be the wrong call for a
// leaver kill switch.
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

const iamDefaultHost = "https://iam.googleapis.com"

// iamHost returns the host used for IAM service-account API calls.
// Tests share urlOverride across Cloud Resource Manager, Cloud
// Identity, and IAM so a single httptest server services every API.
func (c *GCPAccessConnector) iamHost() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return iamDefaultHost
}

type serviceAccountKey struct {
	Name            string `json:"name"`
	KeyType         string `json:"keyType,omitempty"`
	KeyOrigin       string `json:"keyOrigin,omitempty"`
	Disabled        bool   `json:"disabled,omitempty"`
	ValidAfterTime  string `json:"validAfterTime,omitempty"`
	ValidBeforeTime string `json:"validBeforeTime,omitempty"`
}

type listServiceAccountKeysResponse struct {
	Keys []serviceAccountKey `json:"keys"`
}

// RevokeUserSessions disables every key for the supplied service
// account email. NoSuchEntity / 404 on the list or disable call is
// treated as idempotent success (the principal is already gone).
// User-style external IDs (`user:foo@example.com`) are rejected so
// the operator routes them through the correct upstream IdP
// connector.
func (c *GCPAccessConnector) RevokeUserSessions(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	userExternalID string,
) error {
	saEmail, err := parseServiceAccountUser(userExternalID)
	if err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	client, err := c.cloudResourceWriteClient(ctx, cfg, secrets)
	if err != nil {
		return err
	}
	keys, err := c.listServiceAccountKeys(ctx, client, cfg.ProjectID, saEmail)
	if err != nil {
		if isGCPNotFound(err) {
			return nil
		}
		return err
	}
	for _, k := range keys {
		if k.Disabled {
			continue
		}
		// Defence-in-depth: even though listServiceAccountKeys filters
		// by keyTypes=USER_MANAGED, refuse to call keys.disable on
		// SYSTEM_MANAGED entries if the server ever returns them. The
		// upstream API rejects those with FAILED_PRECONDITION and we
		// must not abort the loop on the leaver's other USER_MANAGED
		// keys.
		if strings.EqualFold(k.KeyType, "SYSTEM_MANAGED") {
			continue
		}
		if err := c.disableServiceAccountKey(ctx, client, k.Name); err != nil {
			if isGCPNotFound(err) {
				continue
			}
			return err
		}
	}
	return nil
}

// parseServiceAccountUser strips the optional `serviceAccount:` IAM
// prefix and rejects human user principals.
func parseServiceAccountUser(userExternalID string) (string, error) {
	v := strings.TrimSpace(userExternalID)
	if v == "" {
		return "", errors.New("gcp: session revoke: userExternalID is required")
	}
	if strings.HasPrefix(v, "user:") || strings.HasPrefix(v, "group:") {
		return "", fmt.Errorf("gcp: session revoke: %q is a human / group principal; route human leavers through the google_workspace or IdP connector", v)
	}
	v = strings.TrimPrefix(v, "serviceAccount:")
	if !strings.Contains(v, "@") {
		return "", fmt.Errorf("gcp: session revoke: %q is not a valid service account email", v)
	}
	return v, nil
}

func (c *GCPAccessConnector) listServiceAccountKeys(ctx context.Context, client httpDoer, projectID, saEmail string) ([]serviceAccountKey, error) {
	// Filter to USER_MANAGED keys. Service accounts always have one
	// or more SYSTEM_MANAGED keys (rotated by Google for internal
	// OAuth flows). The IAM keys.disable endpoint rejects
	// SYSTEM_MANAGED keys with FAILED_PRECONDITION, which would
	// abort the revocation loop and leave any subsequent
	// USER_MANAGED keys enabled. Disabling those system-rotated
	// keys also would not kill any human-visible session because the
	// operator never minted them. Listing only USER_MANAGED keys
	// keeps the loop focused on the credentials that automation /
	// on-prem agents actually use to authenticate as the service
	// account.
	// https://cloud.google.com/iam/docs/keys-create-delete#listing-keys
	path := "/v1/projects/" + url.PathEscape(projectID) +
		"/serviceAccounts/" + url.PathEscape(saEmail) + "/keys"
	q := url.Values{}
	q.Set("keyTypes", "USER_MANAGED")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.iamHost()+path+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gcp: list keys: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusNotFound {
		return nil, errGCPNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("gcp: list keys: status %d: %s", resp.StatusCode, string(body))
	}
	var parsed listServiceAccountKeysResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("gcp: decode keys: %w", err)
	}
	return parsed.Keys, nil
}

func (c *GCPAccessConnector) disableServiceAccountKey(ctx context.Context, client httpDoer, keyName string) error {
	// keyName is the full resource path the upstream returned, e.g.
	// projects/{p}/serviceAccounts/{sa}/keys/{kid}. Split-escape so
	// the curly-brace key id can't smuggle URL syntax.
	parts := strings.Split(keyName, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	path := "/v1/" + strings.Join(parts, "/") + ":disable"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.iamHost()+path, strings.NewReader("{}"))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("gcp: disable key: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusNotFound {
		return errGCPNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("gcp: disable key %s: status %d: %s", keyName, resp.StatusCode, string(body))
	}
	return nil
}

// errGCPNotFound is the sentinel surfaced by the helpers when an
// upstream returns 404. isGCPNotFound walks the wrap chain via
// errors.Is so wrapped layers still detect it.
var errGCPNotFound = errors.New("gcp: not found")

func isGCPNotFound(err error) bool {
	return errors.Is(err, errGCPNotFound)
}

var _ access.SessionRevoker = (*GCPAccessConnector)(nil)
