package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// AutoOnboardRule is one matcher in an AutoOnboardingPolicy. An unmanaged asset
// matches a rule when it satisfies EVERY non-empty facet (protocols, sources,
// cidrs). An empty facet does not constrain. Rules are evaluated in order; the
// first match wins and supplies the (optional) per-rule agent binding.
type AutoOnboardRule struct {
	// Name is a human label shown in the policy editor and audit metadata.
	Name string `json:"name"`
	// Protocols restricts the rule to assets with one of these protocols.
	Protocols []string `json:"protocols,omitempty"`
	// Sources restricts the rule to assets from one of these discovery sources.
	Sources []string `json:"sources,omitempty"`
	// CIDRs restricts the rule to assets whose address host is within one of
	// these CIDRs.
	CIDRs []string `json:"cidrs,omitempty"`
	// AgentID binds auto-created targets for this rule to a specific agent,
	// overriding the policy default.
	AgentID *uuid.UUID `json:"agent_id,omitempty"`
}

// PolicyView is the non-secret API representation of an AutoOnboardingPolicy.
// It never carries the sealed credential — only HasCredential + the non-secret
// username — so the editor can show whether a credential is configured without
// exposing it.
type PolicyView struct {
	Enabled        bool              `json:"enabled"`
	CreateTargets  bool              `json:"create_targets"`
	RequireLease   bool              `json:"require_lease"`
	Rules          []AutoOnboardRule `json:"rules"`
	DefaultAgentID *uuid.UUID        `json:"default_agent_id,omitempty"`
	CredentialUser string            `json:"credential_username,omitempty"`
	HasCredential  bool              `json:"has_credential"`
	UpdatedBy      string            `json:"updated_by,omitempty"`
	UpdatedAt      time.Time         `json:"updated_at,omitempty"`
}

// PolicyInput is the operator-supplied policy update. A nil Credential leaves
// any existing sealed credential untouched; a non-nil Credential with an empty
// password clears it (reverting to flag-only).
type PolicyInput struct {
	Enabled        bool
	CreateTargets  bool
	Rules          []AutoOnboardRule
	DefaultAgentID *uuid.UUID
	Credential     *pam.Secret
	Actor          string
}

// GetPolicy returns the workspace's policy as a non-secret view, synthesising a
// safe-default (disabled) view when none has been saved yet.
func (e *Engine) GetPolicy(ctx context.Context, workspaceID uuid.UUID) (PolicyView, error) {
	if workspaceID == uuid.Nil {
		return PolicyView{}, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	policy, err := e.loadPolicy(ctx, workspaceID)
	if err != nil {
		return PolicyView{}, err
	}
	if policy == nil {
		return PolicyView{Enabled: false, CreateTargets: false, RequireLease: true, Rules: []AutoOnboardRule{}}, nil
	}
	return e.policyView(policy)
}

// SavePolicy validates and upserts the workspace's policy. RequireLease is
// pinned true (auto-created targets always require a lease — the documented
// safety boundary). A supplied credential is sealed with the workspace DEK
// (AAD = policy id) before it touches the database; the plaintext never
// persists. The change is audited.
func (e *Engine) SavePolicy(ctx context.Context, workspaceID uuid.UUID, in PolicyInput) (PolicyView, error) {
	if workspaceID == uuid.Nil {
		return PolicyView{}, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if err := validateRules(in.Rules); err != nil {
		return PolicyView{}, err
	}
	rulesJSON, err := json.Marshal(in.Rules)
	if err != nil {
		return PolicyView{}, fmt.Errorf("discovery: marshal rules: %w", err)
	}

	existing, err := e.loadPolicy(ctx, workspaceID)
	if err != nil {
		return PolicyView{}, err
	}
	policy := existing
	if policy == nil {
		policy = &models.AutoOnboardingPolicy{
			Base:        models.Base{ID: uuid.New()},
			WorkspaceID: workspaceID,
		}
	}
	policy.Enabled = in.Enabled
	policy.CreateTargets = in.CreateTargets
	policy.RequireLease = true
	policy.Rules = rulesJSON
	policy.DefaultAgentID = in.DefaultAgentID
	policy.UpdatedBy = in.Actor

	if in.Credential != nil {
		if strings.TrimSpace(in.Credential.Password) == "" && in.Credential.PrivateKey == "" && in.Credential.Token == "" {
			policy.CredentialUsername = ""
			policy.CredentialEnvelope = ""
			policy.CredentialKeyVer = 0
		} else {
			envelope, ver, sealErr := e.sealPolicyCredential(ctx, workspaceID, policy.ID, *in.Credential)
			if sealErr != nil {
				return PolicyView{}, sealErr
			}
			policy.CredentialUsername = strings.TrimSpace(in.Credential.Username)
			policy.CredentialEnvelope = envelope
			policy.CredentialKeyVer = ver
		}
	}

	if in.CreateTargets && policy.CredentialEnvelope == "" {
		return PolicyView{}, fmt.Errorf("%w: create_targets requires an onboarding credential", ErrValidation)
	}

	now := e.now()
	if err := e.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Save(policy).Error; err != nil {
			return fmt.Errorf("discovery: save policy: %w", err)
		}
		return lifecycle.AppendAuditTx(ctx, tx, now, lifecycle.AuditInput{
			WorkspaceID: workspaceID,
			Actor:       in.Actor,
			Action:      "discovery.policy_update",
			TargetRef:   workspaceID.String(),
			Metadata: mustAuditMeta(map[string]any{
				"enabled":        policy.Enabled,
				"create_targets": policy.CreateTargets,
				"rules":          len(in.Rules),
				"has_credential": policy.CredentialEnvelope != "",
			}),
		})
	}); err != nil {
		return PolicyView{}, err
	}
	return e.policyView(policy)
}

func (e *Engine) loadPolicy(ctx context.Context, workspaceID uuid.UUID) (*models.AutoOnboardingPolicy, error) {
	var policy models.AutoOnboardingPolicy
	err := e.db.WithContext(ctx).Where("workspace_id = ?", workspaceID).Take(&policy).Error
	switch {
	case err == nil:
		return &policy, nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		return nil, nil
	default:
		return nil, fmt.Errorf("discovery: load policy: %w", err)
	}
}

func (e *Engine) policyView(policy *models.AutoOnboardingPolicy) (PolicyView, error) {
	rules, err := decodeRules(policy.Rules)
	if err != nil {
		return PolicyView{}, err
	}
	return PolicyView{
		Enabled:        policy.Enabled,
		CreateTargets:  policy.CreateTargets,
		RequireLease:   true,
		Rules:          rules,
		DefaultAgentID: policy.DefaultAgentID,
		CredentialUser: policy.CredentialUsername,
		HasCredential:  policy.CredentialEnvelope != "",
		UpdatedBy:      policy.UpdatedBy,
		UpdatedAt:      policy.UpdatedAt,
	}, nil
}

func (e *Engine) sealPolicyCredential(ctx context.Context, workspaceID, policyID uuid.UUID, secret pam.Secret) (string, int, error) {
	if e.enc == nil {
		return "", 0, fmt.Errorf("%w: credential encryptor not configured", ErrUnsupported)
	}
	plaintext, err := json.Marshal(secret)
	if err != nil {
		return "", 0, fmt.Errorf("discovery: marshal policy credential: %w", err)
	}
	ciphertext, ver, err := e.enc.Encrypt(ctx, workspaceID.String(), plaintext, policyID[:])
	if err != nil {
		return "", 0, fmt.Errorf("discovery: seal policy credential: %w", err)
	}
	return string(ciphertext), ver, nil
}

func (e *Engine) openPolicyCredential(ctx context.Context, policy *models.AutoOnboardingPolicy) (pam.Secret, error) {
	if policy.CredentialEnvelope == "" {
		return pam.Secret{}, fmt.Errorf("%w: policy has no onboarding credential", ErrValidation)
	}
	if e.enc == nil {
		return pam.Secret{}, fmt.Errorf("%w: credential encryptor not configured", ErrUnsupported)
	}
	plaintext, err := e.enc.Decrypt(ctx, policy.WorkspaceID.String(), []byte(policy.CredentialEnvelope), policy.ID[:], policy.CredentialKeyVer)
	if err != nil {
		return pam.Secret{}, fmt.Errorf("discovery: open policy credential: %w", err)
	}
	var secret pam.Secret
	if err := json.Unmarshal(plaintext, &secret); err != nil {
		return pam.Secret{}, fmt.Errorf("discovery: unmarshal policy credential: %w", err)
	}
	return secret, nil
}

func decodeRules(raw []byte) ([]AutoOnboardRule, error) {
	if len(raw) == 0 {
		return []AutoOnboardRule{}, nil
	}
	var rules []AutoOnboardRule
	if err := json.Unmarshal(raw, &rules); err != nil {
		return nil, fmt.Errorf("discovery: decode rules: %w", err)
	}
	if rules == nil {
		rules = []AutoOnboardRule{}
	}
	return rules, nil
}

func validateRules(rules []AutoOnboardRule) error {
	for i, r := range rules {
		if len(r.Protocols) == 0 && len(r.Sources) == 0 && len(r.CIDRs) == 0 {
			return fmt.Errorf("%w: rule %d matches everything; add at least one constraint", ErrValidation, i+1)
		}
		for _, c := range r.CIDRs {
			if _, _, err := net.ParseCIDR(strings.TrimSpace(c)); err != nil {
				return fmt.Errorf("%w: rule %d has invalid cidr %q", ErrValidation, i+1, c)
			}
		}
	}
	return nil
}

// matchRule reports whether an asset satisfies a rule (all non-empty facets).
func matchRule(asset *models.DiscoveredAsset, r AutoOnboardRule) bool {
	if len(r.Protocols) > 0 && !containsFold(r.Protocols, asset.Protocol) {
		return false
	}
	if len(r.Sources) > 0 && !containsFold(r.Sources, asset.Source) {
		return false
	}
	if len(r.CIDRs) > 0 && !addressInAnyCIDR(asset.Address, r.CIDRs) {
		return false
	}
	return true
}

func containsFold(set []string, v string) bool {
	for _, s := range set {
		if strings.EqualFold(strings.TrimSpace(s), v) {
			return true
		}
	}
	return false
}

func addressInAnyCIDR(address string, cidrs []string) bool {
	host := address
	if h, _, err := net.SplitHostPort(address); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, c := range cidrs {
		_, ipnet, err := net.ParseCIDR(strings.TrimSpace(c))
		if err != nil {
			continue
		}
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}
