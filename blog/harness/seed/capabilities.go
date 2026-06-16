package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/blog/harness/harnesskit"
	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/discovery"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// seedAccessCapabilities lights up the three privileged-access surfaces the
// older seed left in their empty state so the console renders them populated
// with real data:
//
//   - seedOnlineAgent materialises an ONLINE outbound connector agent (A) plus
//     the reachable destinations it self-reports from inside the private
//     network. The agent ROW is the one seam we write directly: the durable
//     post-registration record the mTLS enrollment produces, since the live
//     yamux tunnel exists only in the relay process and cannot be faked from a
//     seed binary. Everything downstream of it is a genuine service call.
//   - seedDiscoveryInventory runs the real discovery reconcile (E) over that
//     agent's self-report, onboards one asset through the production PAM vault
//     (so it shows managed alongside the unmanaged candidates), and saves an
//     opt-in auto-onboarding policy — the same code paths the API invokes.
//   - seedRotationSchedules configures interval + dynamic credential rotation
//     (C) on existing PAM targets through RotationPolicyService.UpsertPolicy,
//     so the rotation console shows live schedules and ephemeral-cred issuance
//     instead of "Not Configured" rows.
//
// Idempotent per workspace: re-running the seed never duplicates an agent,
// asset, or policy.
func (s *seeder) seedAccessCapabilities(ws harnesskit.Workspace, workspaceID uuid.UUID) {
	ctx := context.Background()
	agentID := s.seedOnlineAgent(ctx, ws, workspaceID)
	if agentID != uuid.Nil {
		s.seedDiscoveryInventory(ctx, ws, workspaceID, agentID)
	}
	s.seedRotationSchedules(ctx, ws, workspaceID)
}

// seedOnlineAgent provisions one online outbound connector agent for the
// workspace and the network destinations it advertises it can reach. Returns
// the agent id (or the existing one) so discovery can import its reach.
func (s *seeder) seedOnlineAgent(ctx context.Context, ws harnesskit.Workspace, workspaceID uuid.UUID) uuid.UUID {
	var existing models.TargetAgent
	err := s.db.WithContext(ctx).
		Where("workspace_id = ?", workspaceID).
		Order("created_at asc").
		Take(&existing).Error
	if err == nil {
		harnesskit.Logf("SKIP %s: connector agent already enrolled (%s)", ws.Slug, existing.ID)
		return existing.ID
	}

	now := time.Now().UTC()
	name := ws.Slug + "-edge-01"
	sum := sha256.Sum256([]byte("blog-seed-agent:" + name))
	fp := hex.EncodeToString(sum[:])
	agent := &models.TargetAgent{
		WorkspaceID:     workspaceID,
		Name:            name,
		CertFingerprint: fp,
		CertSerial:      fp[:32],
		CertNotAfter:    now.Add(365 * 24 * time.Hour),
		Status:          models.AgentStatusOnline,
		LastSeenAt:      &now,
		AgentVersion:    "1.6.0",
		Platform:        "linux/amd64",
	}
	if err := s.db.WithContext(ctx).Create(agent).Error; err != nil {
		harnesskit.Logf("WARN %s: create connector agent: %v", ws.Slug, err)
		return uuid.Nil
	}

	// Self-reported reachable bindings: a private CIDR plus concrete host:port
	// destinations whose ports infer a protocol, so the discovery import turns
	// them into protocol-typed assets an admin can one-click onboard.
	reach := []struct {
		pattern string
		kind    string
	}{
		{"10.20.0.0/24", models.AgentReachKindCIDR},
		{"db-primary.corp.internal:5432", models.AgentReachKindHost},
		{"reporting-db.corp.internal:3306", models.AgentReachKindHost},
		{"bastion.corp.internal:22", models.AgentReachKindHost},
		{"build-01.corp.internal:22", models.AgentReachKindHost},
	}
	for _, r := range reach {
		row := &models.AgentReachableTarget{
			WorkspaceID: workspaceID,
			AgentID:     agent.ID,
			Pattern:     r.pattern,
			Kind:        r.kind,
		}
		if err := s.db.WithContext(ctx).Create(row).Error; err != nil {
			harnesskit.Logf("WARN %s: create reachable target %s: %v", ws.Slug, r.pattern, err)
		}
	}
	harnesskit.Logf("OK   %s: online connector agent %s (%d reachable bindings)", ws.Slug, agent.ID, len(reach))
	return agent.ID
}

// discoveryEngine builds a discovery Engine over the same vault/DEK path the
// control plane uses, so an onboarded target seals its credential identically.
func (s *seeder) discoveryEngine() (*discovery.Engine, bool) {
	enc, err := access.CredentialEncryptorFromConfig(os.Getenv("ACCESS_KMS_MASTER_KEY"), kmsKeyVersion(), os.Getenv("ACCESS_CREDENTIAL_DEK"))
	if err != nil {
		harnesskit.Logf("WARN: build discovery encryptor: %v", err)
		return nil, false
	}
	return discovery.NewEngine(s.db, pam.NewVault(s.db, enc, nil)), true
}

// seedDiscoveryInventory imports the agent's self-reported reach into the
// discovered-asset surface (real reconcile), onboards one bastion so the
// inventory shows a managed/unmanaged mix, and saves an opt-in auto-onboarding
// policy for the policy editor.
func (s *seeder) seedDiscoveryInventory(ctx context.Context, ws harnesskit.Workspace, workspaceID, agentID uuid.UUID) {
	engine, ok := s.discoveryEngine()
	if !ok {
		return
	}
	actor := ws.OwnerSub()

	if _, err := engine.ImportAgentReachable(ctx, workspaceID, agentID, actor); err != nil {
		harnesskit.Logf("WARN %s: import agent-reachable assets: %v", ws.Slug, err)
		return
	}

	assets, err := engine.ListAssets(ctx, workspaceID, discovery.AssetFilter{})
	if err != nil {
		harnesskit.Logf("WARN %s: list discovered assets: %v", ws.Slug, err)
		return
	}

	// Onboard the first unmanaged SSH bastion so the inventory shows one managed
	// asset next to the unmanaged candidates. Best-effort and idempotent: a
	// second run finds the asset already managed and leaves it.
	onboarded := false
	for i := range assets {
		a := assets[i]
		if a.Status != models.DiscoveryStatusUnmanaged || a.Protocol != models.PAMProtocolSSH || a.Address == "" {
			continue
		}
		if _, err := engine.OnboardAsset(ctx, workspaceID, a.ID, discovery.OnboardAssetInput{
			Username:   "svc_access",
			Secret:     pam.Secret{Username: "svc_access", Password: "demo-not-a-real-credential"},
			AgentID:    &agentID,
			RequireMFA: true,
			Actor:      actor,
		}); err != nil {
			harnesskit.Logf("WARN %s: onboard discovered asset %s: %v", ws.Slug, a.Address, err)
			continue
		}
		onboarded = true
		break
	}

	// Opt-in auto-onboarding policy in recommend-only mode (CreateTargets=false):
	// it surfaces candidates without minting targets, the safe default we want a
	// reader to see in the policy editor.
	if _, err := engine.SavePolicy(ctx, workspaceID, discovery.PolicyInput{
		Enabled:       true,
		CreateTargets: false,
		Rules: []discovery.AutoOnboardRule{
			{Name: "SSH bastions", Protocols: []string{models.PAMProtocolSSH}, Sources: []string{models.DiscoverySourceAgentSweep}},
		},
		Actor: actor,
	}); err != nil {
		harnesskit.Logf("WARN %s: save auto-onboarding policy: %v", ws.Slug, err)
	}

	harnesskit.Logf("OK   %s: discovered %d assets (onboarded=%t), saved auto-onboarding policy", ws.Slug, len(assets), onboarded)
}

// seedRotationSchedules configures credential-rotation policies on the
// workspace's PAM targets so the rotation console shows live schedules: a
// postgres target rotates on an interval AND issues ephemeral per-lease
// credentials; an ssh target rotates after every check-in.
func (s *seeder) seedRotationSchedules(ctx context.Context, ws harnesskit.Workspace, workspaceID uuid.UUID) {
	enc, err := access.CredentialEncryptorFromConfig(os.Getenv("ACCESS_KMS_MASTER_KEY"), kmsKeyVersion(), os.Getenv("ACCESS_CREDENTIAL_DEK"))
	if err != nil {
		harnesskit.Logf("WARN %s: build rotation encryptor: %v", ws.Slug, err)
		return
	}
	svc := pam.NewRotationPolicyService(s.db, pam.NewVault(s.db, enc, nil), pam.NewExecutorRegistry(10*time.Second))

	var targets []models.PAMTarget
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ?", workspaceID).
		Order("created_at asc").
		Find(&targets).Error; err != nil {
		harnesskit.Logf("WARN %s: list pam targets for rotation: %v", ws.Slug, err)
		return
	}

	pgDone, sshDone := false, false
	for i := range targets {
		t := targets[i]
		switch {
		case !pgDone && t.Protocol == models.PAMProtocolPostgres:
			if _, err := svc.UpsertPolicy(ctx, workspaceID, t.ID, pam.PolicyInput{
				Mode:              models.RotationModeInterval,
				IntervalSeconds:   int64((7 * 24 * time.Hour).Seconds()),
				DynamicEnabled:    true,
				DynamicTTLSeconds: int64((1 * time.Hour).Seconds()),
				Enabled:           true,
			}, ws.OwnerSub()); err != nil {
				harnesskit.Logf("WARN %s: configure interval rotation on %s: %v", ws.Slug, t.Name, err)
			} else {
				pgDone = true
			}
		case !sshDone && t.Protocol == models.PAMProtocolSSH:
			if _, err := svc.UpsertPolicy(ctx, workspaceID, t.ID, pam.PolicyInput{
				Mode:            models.RotationModeDisabled,
				RotateOnCheckin: true,
				Enabled:         true,
			}, ws.OwnerSub()); err != nil {
				harnesskit.Logf("WARN %s: configure checkin rotation on %s: %v", ws.Slug, t.Name, err)
			} else {
				sshDone = true
			}
		}
	}
	harnesskit.Logf("OK   %s: rotation configured (interval+dynamic=%t, checkin=%t)", ws.Slug, pgDone, sshDone)
}
