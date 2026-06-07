package wasabi

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// advanced-capability mapping for wasabi (IAM-compatible):
//
//   - ProvisionAccess  -> Action=AttachUserPolicy
//   - RevokeAccess     -> Action=DetachUserPolicy
//   - ListEntitlements -> Action=ListAttachedUserPolicies
//
// AccessGrant maps:
//   - grant.UserExternalID     -> IAM UserName
//   - grant.ResourceExternalID -> IAM PolicyArn
//
// SigV4 signing reuses the existing aws helpers via the package-local
// signRequestSigV4 wrapper. Idempotent on (UserExternalID,
// ResourceExternalID): IAM returns 409 EntityAlreadyExists on
// duplicate attach and 404 NoSuchEntity on duplicate detach.

func wasabiValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("wasabi: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("wasabi: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *WasabiAccessConnector) callIAMRaw(ctx context.Context, secrets Secrets, params url.Values) (int, []byte, error) {
	if params.Get("Version") == "" {
		params.Set("Version", iamAPIVersion)
	}
	body := params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL(), strings.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("Accept", "application/xml")
	if err := signRequestSigV4(req, secrets.AccessKeyID, secrets.SecretAccessKey, defaultRegion, "iam", c.now()); err != nil {
		return 0, nil, fmt.Errorf("wasabi: sign: %w", err)
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("wasabi: %s: network error", params.Get("Action"))
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, respBody, nil
}

func (c *WasabiAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := wasabiValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	params := url.Values{}
	params.Set("Action", "AttachUserPolicy")
	params.Set("UserName", strings.TrimSpace(grant.UserExternalID))
	params.Set("PolicyArn", strings.TrimSpace(grant.ResourceExternalID))
	status, body, err := c.callIAMRaw(ctx, secrets, params)
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case access.IsIdempotentProvisionStatus(status, body):
		return nil
	case strings.Contains(string(body), "EntityAlreadyExists"):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("wasabi: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("wasabi: provision status %d: %s", status, string(body))
	}
}

func (c *WasabiAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := wasabiValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	params := url.Values{}
	params.Set("Action", "DetachUserPolicy")
	params.Set("UserName", strings.TrimSpace(grant.UserExternalID))
	params.Set("PolicyArn", strings.TrimSpace(grant.ResourceExternalID))
	status, body, err := c.callIAMRaw(ctx, secrets, params)
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case access.IsIdempotentRevokeStatus(status, body):
		return nil
	case strings.Contains(string(body), "NoSuchEntity"):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("wasabi: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("wasabi: revoke status %d: %s", status, string(body))
	}
}

func (c *WasabiAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("wasabi: user external id is required")
	}
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	params := url.Values{}
	params.Set("Action", "ListAttachedUserPolicies")
	params.Set("UserName", user)
	status, body, err := c.callIAMRaw(ctx, secrets, params)
	if err != nil {
		return nil, err
	}
	if strings.Contains(string(body), "NoSuchEntity") {
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("wasabi: list entitlements status %d: %s", status, string(body))
	}
	var envelope struct {
		XMLName xml.Name `xml:"ListAttachedUserPoliciesResponse"`
		Result  struct {
			AttachedPolicies []struct {
				PolicyName string `xml:"PolicyName"`
				PolicyArn  string `xml:"PolicyArn"`
			} `xml:"AttachedPolicies>member"`
		} `xml:"ListAttachedUserPoliciesResult"`
	}
	if err := xml.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("wasabi: decode entitlements: %w", err)
	}
	out := make([]access.Entitlement, 0, len(envelope.Result.AttachedPolicies))
	for _, p := range envelope.Result.AttachedPolicies {
		out = append(out, access.Entitlement{
			ResourceExternalID: strings.TrimSpace(p.PolicyArn),
			Role:               strings.TrimSpace(p.PolicyName),
			Source:             "direct",
		})
	}
	return out, nil
}
