// Package gemini — advanced lifecycle capabilities backed by Google Cloud
// Resource Manager IAM. Vertex AI / Google AI Studio access is granted by
// binding an IAM principal to a role (default roles/aiplatform.user) on the
// containing project. This file maps the canonical
// ProvisionAccess / RevokeAccess / ListEntitlements verbs onto the
// :getIamPolicy / :setIamPolicy operations exposed at
// https://cloudresourcemanager.googleapis.com/v1/projects/{projectID}.
package gemini

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// defaultGeminiRole is the role bound when the caller does not supply a
// role explicitly via grant.Role or grant.ResourceExternalID. It matches
// the documented Vertex AI / Gemini predefined role for end users.
const defaultGeminiRole = "roles/aiplatform.user"

// iamBaseURL returns the Cloud Resource Manager base URL. When
// urlOverride is set (tests), every google.com base URL collapses onto
// the test server so the httptest handler can route by path prefix.
func (c *GeminiAccessConnector) iamBaseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://cloudresourcemanager.googleapis.com"
}

type geminiBinding struct {
	Role    string   `json:"role"`
	Members []string `json:"members"`
}

type geminiPolicy struct {
	Version  int             `json:"version,omitempty"`
	Bindings []geminiBinding `json:"bindings"`
	Etag     string          `json:"etag,omitempty"`
}

type geminiGetIamPolicyRequest struct {
	Options geminiGetIamPolicyOptions `json:"options"`
}

type geminiGetIamPolicyOptions struct {
	RequestedPolicyVersion int `json:"requestedPolicyVersion"`
}

type geminiSetIamPolicyRequest struct {
	Policy geminiPolicy `json:"policy"`
}

// principal returns the IAM member spelling for the given UserExternalID.
// Callers may pre-qualify (e.g. "serviceAccount:svc@...", "group:...") and
// the function preserves the prefix; bare emails are treated as
// `user:{email}` per the IAM v1 convention.
func principal(externalID string) string {
	id := strings.TrimSpace(externalID)
	if id == "" {
		return ""
	}
	switch {
	case strings.HasPrefix(id, "user:"),
		strings.HasPrefix(id, "serviceAccount:"),
		strings.HasPrefix(id, "group:"),
		strings.HasPrefix(id, "domain:"):
		return id
	}
	return "user:" + id
}

// roleFromGrant resolves the role to bind, preferring grant.Role, then
// grant.ResourceExternalID (for callers that scope by role identifier),
// falling back to defaultGeminiRole.
func roleFromGrant(grant access.AccessGrant) string {
	if r := strings.TrimSpace(grant.Role); r != "" {
		return r
	}
	if r := strings.TrimSpace(grant.ResourceExternalID); r != "" {
		return r
	}
	return defaultGeminiRole
}

func (c *GeminiAccessConnector) projectIamURL(cfg Config, verb string) string {
	return c.iamBaseURL() + "/v1/projects/" + url.PathEscape(strings.TrimSpace(cfg.ProjectID)) + ":" + verb
}

func (c *GeminiAccessConnector) postJSON(ctx context.Context, secrets Secrets, fullURL string, payload []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return c.do(req)
}

// getIamPolicy fetches the current project IAM policy. Cloud Resource
// Manager's :getIamPolicy is a POST that returns the full policy plus an
// etag for optimistic concurrency control on the matching :setIamPolicy.
func (c *GeminiAccessConnector) getIamPolicy(ctx context.Context, secrets Secrets, cfg Config) (*geminiPolicy, error) {
	body, err := json.Marshal(geminiGetIamPolicyRequest{Options: geminiGetIamPolicyOptions{RequestedPolicyVersion: 3}})
	if err != nil {
		return nil, err
	}
	out, err := c.postJSON(ctx, secrets, c.projectIamURL(cfg, "getIamPolicy"), body)
	if err != nil {
		return nil, err
	}
	var pol geminiPolicy
	if err := json.Unmarshal(out, &pol); err != nil {
		return nil, fmt.Errorf("gemini: decode getIamPolicy: %w", err)
	}
	return &pol, nil
}

// setIamPolicy replaces the project IAM policy. The caller is expected to
// have just read the policy and to forward the unchanged etag so that
// concurrent mutations fail-fast instead of overwriting.
func (c *GeminiAccessConnector) setIamPolicy(ctx context.Context, secrets Secrets, cfg Config, pol *geminiPolicy) error {
	body, err := json.Marshal(geminiSetIamPolicyRequest{Policy: *pol})
	if err != nil {
		return err
	}
	_, err = c.postJSON(ctx, secrets, c.projectIamURL(cfg, "setIamPolicy"), body)
	return err
}

// ProvisionAccess binds the grant's principal to the requested role on
// the project IAM policy. The call is idempotent on
// (UserExternalID, ResourceExternalID): an already-present binding short
// circuits without issuing :setIamPolicy.
func (c *GeminiAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	member := principal(grant.UserExternalID)
	if member == "" {
		return errors.New("gemini: ProvisionAccess: UserExternalID is required")
	}
	role := roleFromGrant(grant)
	pol, err := c.getIamPolicy(ctx, secrets, cfg)
	if err != nil {
		return err
	}
	for i := range pol.Bindings {
		if pol.Bindings[i].Role != role {
			continue
		}
		for _, m := range pol.Bindings[i].Members {
			if m == member {
				return nil
			}
		}
		pol.Bindings[i].Members = append(pol.Bindings[i].Members, member)
		return c.setIamPolicy(ctx, secrets, cfg, pol)
	}
	pol.Bindings = append(pol.Bindings, geminiBinding{Role: role, Members: []string{member}})
	return c.setIamPolicy(ctx, secrets, cfg, pol)
}

// RevokeAccess removes the grant's principal from the requested role's
// member list. Idempotent: an absent member short circuits without
// issuing :setIamPolicy.
func (c *GeminiAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	member := principal(grant.UserExternalID)
	if member == "" {
		return errors.New("gemini: RevokeAccess: UserExternalID is required")
	}
	role := roleFromGrant(grant)
	pol, err := c.getIamPolicy(ctx, secrets, cfg)
	if err != nil {
		return err
	}
	for i := range pol.Bindings {
		if pol.Bindings[i].Role != role {
			continue
		}
		before := len(pol.Bindings[i].Members)
		pol.Bindings[i].Members = slices.DeleteFunc(pol.Bindings[i].Members, func(m string) bool {
			return m == member
		})
		if len(pol.Bindings[i].Members) == before {
			return nil
		}
		return c.setIamPolicy(ctx, secrets, cfg, pol)
	}
	return nil
}

// ListEntitlements returns every project-level IAM role bound to the
// given principal. ResourceExternalID is the fully-qualified project
// resource name so downstream graph consumers can correlate with
// SyncIdentities output.
func (c *GeminiAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, externalUserID string) ([]access.Entitlement, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	member := principal(externalUserID)
	if member == "" {
		return nil, errors.New("gemini: ListEntitlements: externalUserID is required")
	}
	pol, err := c.getIamPolicy(ctx, secrets, cfg)
	if err != nil {
		return nil, err
	}
	resource := "projects/" + strings.TrimSpace(cfg.ProjectID)
	out := make([]access.Entitlement, 0)
	for _, b := range pol.Bindings {
		for _, m := range b.Members {
			if m == member {
				out = append(out, access.Entitlement{
					ResourceExternalID: resource,
					Role:               b.Role,
					Source:             "direct",
				})
				break
			}
		}
	}
	return out, nil
}
