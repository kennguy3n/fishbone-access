package alibaba

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

// advanced-capability mapping for alibaba (RAM):
//
//   - ProvisionAccess  -> Action=AttachPolicyToUser
//   - RevokeAccess     -> Action=DetachPolicyFromUser
//   - ListEntitlements -> Action=ListPoliciesForUser
//
// AccessGrant maps:
//   - grant.UserExternalID     -> RAM user name
//   - grant.ResourceExternalID -> RAM policy name. Optional PolicyType
//     is inferred to "Custom" by default; for "System/PolicyName" syntax
//     it splits on the first '/'.
//
// HMAC-SHA1 GET signing is reused from the existing sign() / nonce()
// helpers. Idempotent on (UserExternalID, ResourceExternalID): RAM
// returns EntityAlreadyExist.User.Policy on duplicate attach and
// EntityNotExist.User.Policy on duplicate detach.

func alibabaValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("alibaba: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("alibaba: grant.ResourceExternalID is required")
	}
	return nil
}

func splitPolicyTypeAndName(resource string) (policyType, name string) {
	resource = strings.TrimSpace(resource)
	if i := strings.Index(resource, "/"); i > 0 {
		return resource[:i], resource[i+1:]
	}
	return "Custom", resource
}

// callRAMRaw is identical to callRAM but returns the HTTP status code
// and response body without mapping non-2xx to an error, so the
// advanced-capability methods can apply IsIdempotentProvisionStatus /
// IsIdempotentRevokeStatus.
func (c *AlibabaAccessConnector) callRAMRaw(ctx context.Context, secrets Secrets, action string, extra map[string]string) (int, []byte, error) {
	params := map[string]string{
		"Format":           "JSON",
		"Version":          ramAPIVersion,
		"AccessKeyId":      strings.TrimSpace(secrets.AccessKeyID),
		"SignatureMethod":  signatureMethod,
		"Timestamp":        c.now().UTC().Format("2006-01-02T15:04:05Z"),
		"SignatureVersion": signatureVersion,
		"SignatureNonce":   c.nonce(),
		"Action":           action,
	}
	for k, v := range extra {
		params[k] = v
	}
	signature := sign(strings.TrimSpace(secrets.AccessKeySecret), params, http.MethodGet)
	params["Signature"] = signature
	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	full := c.baseURL() + "?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("alibaba: %s: network error", action)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *AlibabaAccessConnector) ProvisionAccess(ctx context.Context, _, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := alibabaValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(map[string]interface{}{}, secretsRaw)
	if err != nil {
		return err
	}
	policyType, policyName := splitPolicyTypeAndName(grant.ResourceExternalID)
	status, body, err := c.callRAMRaw(ctx, secrets, "AttachPolicyToUser", map[string]string{
		"UserName":   strings.TrimSpace(grant.UserExternalID),
		"PolicyName": policyName,
		"PolicyType": policyType,
	})
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case access.IsIdempotentProvisionStatus(status, body):
		return nil
	case bytesContains(body, "EntityAlreadyExist"):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("alibaba: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("alibaba: provision status %d: %s", status, string(body))
	}
}

func (c *AlibabaAccessConnector) RevokeAccess(ctx context.Context, _, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := alibabaValidateGrant(grant); err != nil {
		return err
	}
	_, secrets, err := c.decodeBoth(map[string]interface{}{}, secretsRaw)
	if err != nil {
		return err
	}
	policyType, policyName := splitPolicyTypeAndName(grant.ResourceExternalID)
	status, body, err := c.callRAMRaw(ctx, secrets, "DetachPolicyFromUser", map[string]string{
		"UserName":   strings.TrimSpace(grant.UserExternalID),
		"PolicyName": policyName,
		"PolicyType": policyType,
	})
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case access.IsIdempotentRevokeStatus(status, body):
		return nil
	case bytesContains(body, "EntityNotExist"):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("alibaba: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("alibaba: revoke status %d: %s", status, string(body))
	}
}

func (c *AlibabaAccessConnector) ListEntitlements(ctx context.Context, _, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("alibaba: user external id is required")
	}
	_, secrets, err := c.decodeBoth(map[string]interface{}{}, secretsRaw)
	if err != nil {
		return nil, err
	}
	status, body, err := c.callRAMRaw(ctx, secrets, "ListPoliciesForUser", map[string]string{
		"UserName": user,
	})
	if err != nil {
		return nil, err
	}
	if bytesContains(body, "EntityNotExist") {
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("alibaba: list entitlements status %d: %s", status, string(body))
	}
	var envelope struct {
		Policies struct {
			Policy []struct {
				PolicyName string `json:"PolicyName"`
				PolicyType string `json:"PolicyType"`
			} `json:"Policy"`
		} `json:"Policies"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("alibaba: decode entitlements: %w", err)
	}
	out := make([]access.Entitlement, 0, len(envelope.Policies.Policy))
	for _, p := range envelope.Policies.Policy {
		role := strings.TrimSpace(p.PolicyName)
		if p.PolicyType != "" {
			role = strings.TrimSpace(p.PolicyType) + "/" + role
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: role,
			Role:               strings.TrimSpace(p.PolicyName),
			Source:             "direct",
		})
	}
	return out, nil
}

func bytesContains(body []byte, needle string) bool {
	return strings.Contains(string(body), needle)
}
