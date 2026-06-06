// Package aws — SessionRevoker implementation.
//
// AWS IAM lacks a direct "kill active sessions" API. The strongest
// documented combination available through the public IAM surface is:
//
//  1. iam:DeleteLoginProfile — removes the user's console password,
//     immediately invalidating new console sign-ins (existing console
//     session cookies expire on their own ~15-60 min TTL).
//  2. iam:ListAccessKeys + iam:DeleteAccessKey for every key —
//     deletes all programmatic access keys, immediately invalidating
//     all API calls signed with those keys (other connectors used by
//     CLI/SDK).
//
// Together these revoke both interactive and programmatic surface
// area. Existing federated STS / SSO sessions issued before deletion
// are NOT revoked by these calls — that requires the separate
// "AWSRevokeOlderSessions" inline policy attachment on every role
// (described in the IAM user guide § "Revoking IAM Role Temporary
// Security Credentials"), which is a more invasive change. We do not
// attach AWSRevokeOlderSessions here because (a) it requires touching
// every role, not just the user, and (b) IAM users typically don't
// federate. Document this gap so the leaver flow can surface the
// trade-off to operators.
//
// All operations are idempotent on NoSuchEntity (404-equivalent for
// IAM). Empty userExternalID is rejected with an error per the
// SessionRevoker contract.
package aws

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// RevokeUserSessions deletes the user's login profile (console
// password) and all their access keys. userExternalID must be the
// IAM UserName — IAM's per-user mutation APIs are keyed by name,
// not UserId. NoSuchEntity is treated as idempotent success.
func (c *AWSAccessConnector) RevokeUserSessions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) error {
	userExternalID = strings.TrimSpace(userExternalID)
	if userExternalID == "" {
		return errors.New("aws: session revoke: userExternalID (IAM UserName) is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}

	if err := c.deleteLoginProfile(ctx, cfg, secrets, userExternalID); err != nil {
		return err
	}
	if err := c.deleteAllAccessKeys(ctx, cfg, secrets, userExternalID); err != nil {
		return err
	}
	return nil
}

func (c *AWSAccessConnector) deleteLoginProfile(ctx context.Context, cfg Config, secrets Secrets, userName string) error {
	params := url.Values{}
	params.Set("Action", "DeleteLoginProfile")
	params.Set("UserName", userName)
	if _, err := c.callIAM(ctx, cfg, secrets, params); err != nil {
		if isAWSErrorCode(err, "NoSuchEntity") {
			return nil
		}
		return fmt.Errorf("aws: DeleteLoginProfile: %w", err)
	}
	return nil
}

func (c *AWSAccessConnector) deleteAllAccessKeys(ctx context.Context, cfg Config, secrets Secrets, userName string) error {
	marker := ""
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		params := url.Values{}
		params.Set("Action", "ListAccessKeys")
		params.Set("UserName", userName)
		params.Set("MaxItems", "100")
		if marker != "" {
			params.Set("Marker", marker)
		}
		body, err := c.callIAM(ctx, cfg, secrets, params)
		if err != nil {
			if isAWSErrorCode(err, "NoSuchEntity") {
				return nil
			}
			return fmt.Errorf("aws: ListAccessKeys: %w", err)
		}
		var resp listAccessKeysResponse
		if err := xml.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("aws: decode ListAccessKeys: %w", err)
		}
		for _, k := range resp.ListAccessKeysResult.AccessKeyMetadata {
			if k.AccessKeyID == "" {
				continue
			}
			delParams := url.Values{}
			delParams.Set("Action", "DeleteAccessKey")
			delParams.Set("UserName", userName)
			delParams.Set("AccessKeyId", k.AccessKeyID)
			if _, err := c.callIAM(ctx, cfg, secrets, delParams); err != nil {
				if isAWSErrorCode(err, "NoSuchEntity") {
					continue
				}
				return fmt.Errorf("aws: DeleteAccessKey %s: %w", k.AccessKeyID, err)
			}
		}
		if !resp.ListAccessKeysResult.IsTruncated {
			return nil
		}
		marker = resp.ListAccessKeysResult.Marker
		if marker == "" {
			return nil
		}
	}
}

var _ access.SessionRevoker = (*AWSAccessConnector)(nil)
