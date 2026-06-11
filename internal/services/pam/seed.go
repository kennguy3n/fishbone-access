package pam

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// Seeder drives a complete privileged-session scenario through the real PAM
// control plane — mint a connect token, redeem it to open a session, log the
// operator's commands, anchor the recording reference, and close the session —
// so a demo or test run produces genuine CC6.7 / A.8.2 evidence in the audit
// hash chain rather than synthetic rows poked directly into the table. Because
// it composes the production Vault / Broker / SessionManager, every event it
// emits is identical to one a live gateway would emit; nothing here is a
// test-only shortcut.
//
// It is deliberately a thin, dependency-light orchestration so it can be reused
// from anywhere that already has the PAM services wired (a seed harness, an
// integration test, a demo bootstrap) without dragging in the gateway: the
// recording bytes/digest are computed by the gateway recorder and passed in as
// a RecordingRef, keeping the dependency pointing gateway → pam.
type Seeder struct {
	vault    *Vault
	broker   *Broker
	sessions *SessionManager
}

// NewSeeder wires a scenario seeder over the real PAM services. All three are
// required: the vault resolves/creates the target, the broker mints+redeems the
// connect token, and the session manager logs commands and ends the session.
func NewSeeder(vault *Vault, broker *Broker, sessions *SessionManager) *Seeder {
	return &Seeder{vault: vault, broker: broker, sessions: sessions}
}

// SeedPrivilegedSessionInput parametrises one seeded privileged session. The
// target is resolved by id when TargetID is set, otherwise by name (created on
// first use so the seeder is idempotent across repeated demo runs — a second
// run with the same TargetName reuses the existing target instead of
// duplicating it). Commands are logged in order; Recording, when its Key is
// set, is anchored as the session's tamper-evident recording reference.
type SeedPrivilegedSessionInput struct {
	WorkspaceID uuid.UUID
	Subject     string
	Actor       string

	// Target selection. Prefer TargetID; otherwise the seeder ensures a target
	// named TargetName exists, creating it with the connection fields + Secret
	// when absent.
	TargetID   uuid.UUID
	TargetName string
	Protocol   string
	Address    string
	Username   string
	Secret     Secret

	ClientAddr string
	Commands   []string
	Recording  RecordingRef
}

// SeedPrivilegedSessionResult reports what the scenario produced so a caller
// (or assertion) can tie the seeded evidence back to concrete ids.
type SeedPrivilegedSessionResult struct {
	Target   *models.PAMTarget
	Session  *models.PAMSession
	Commands int
	Recorded bool
}

// SeedPrivilegedSession runs the full open → command(s) → recording → close
// lifecycle for one privileged session. Each step appends its own chained audit
// event (pam.session.opened, pam.command, pam.session.recording,
// pam.session.closed), so after this returns the workspace chain carries a
// complete, control-mapped privileged-access evidence trail. The session is
// always closed before returning (best-effort) so a seeded scenario never
// leaves a dangling Active session behind.
func (s *Seeder) SeedPrivilegedSession(ctx context.Context, in SeedPrivilegedSessionInput) (*SeedPrivilegedSessionResult, error) {
	if s == nil || s.vault == nil || s.broker == nil || s.sessions == nil {
		return nil, fmt.Errorf("pam: Seeder not initialised")
	}
	if in.WorkspaceID == uuid.Nil {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if strings.TrimSpace(in.Subject) == "" {
		return nil, fmt.Errorf("%w: subject is required", ErrValidation)
	}

	// Resolve the acting principal once, before any work, so every audit event
	// the scenario emits — including the pam.target.created row written when
	// ensureTarget creates the target on first use — attributes to the same
	// actor rather than leaving the target-creation event unattributed.
	actor := in.Actor
	if actor == "" {
		actor = in.Subject
	}
	in.Actor = actor

	target, err := s.ensureTarget(ctx, in)
	if err != nil {
		return nil, err
	}

	rawToken, _, err := s.broker.MintConnectToken(ctx, MintInput{
		WorkspaceID: in.WorkspaceID,
		TargetID:    target.ID,
		Subject:     in.Subject,
		Actor:       actor,
	})
	if err != nil {
		return nil, fmt.Errorf("pam: seed mint connect token: %w", err)
	}

	clientAddr := in.ClientAddr
	if clientAddr == "" {
		clientAddr = "seed"
	}
	leased, err := s.broker.RedeemConnectToken(ctx, rawToken, clientAddr)
	if err != nil {
		return nil, fmt.Errorf("pam: seed redeem connect token: %w", err)
	}
	session := leased.Session

	result := &SeedPrivilegedSessionResult{Target: target, Session: session}

	for _, cmd := range in.Commands {
		if strings.TrimSpace(cmd) == "" {
			continue
		}
		if _, err := s.sessions.LogCommand(ctx, session, cmd); err != nil {
			// Close the session we opened before surfacing the error so the
			// scenario does not strand an Active session on a mid-run failure.
			_ = s.sessions.CloseSession(ctx, in.WorkspaceID, session.ID)
			return nil, fmt.Errorf("pam: seed log command: %w", err)
		}
		result.Commands++
	}

	if in.Recording.Key != "" {
		if err := s.sessions.RecordRecording(ctx, session, in.Recording); err != nil {
			_ = s.sessions.CloseSession(ctx, in.WorkspaceID, session.ID)
			return nil, fmt.Errorf("pam: seed record recording: %w", err)
		}
		result.Recorded = true
	}

	if err := s.sessions.CloseSession(ctx, in.WorkspaceID, session.ID); err != nil {
		return nil, fmt.Errorf("pam: seed close session: %w", err)
	}
	return result, nil
}

// ensureTarget resolves the scenario's target, creating one by name on first
// use. Resolution by id is exact; resolution by name is an exact, workspace-
// scoped lookup so repeated seed runs converge on a single target rather than
// accumulating duplicates — even for workspaces whose target catalog exceeds a
// single ListTargets page.
func (s *Seeder) ensureTarget(ctx context.Context, in SeedPrivilegedSessionInput) (*models.PAMTarget, error) {
	if in.TargetID != uuid.Nil {
		return s.vault.GetTarget(ctx, in.WorkspaceID, in.TargetID)
	}
	name := strings.TrimSpace(in.TargetName)
	if name == "" {
		return nil, fmt.Errorf("%w: target_id or target_name is required", ErrValidation)
	}

	// Reuse an existing target with the same name so the seeder is idempotent.
	// An exact name lookup (rather than scanning a capped ListTargets) keeps this
	// correct regardless of how many targets the workspace already holds.
	switch existing, err := s.vault.FindTargetByName(ctx, in.WorkspaceID, name); {
	case err == nil:
		return existing, nil
	case !errors.Is(err, ErrTargetNotFound):
		return nil, err
	}

	protocol := in.Protocol
	if protocol == "" {
		protocol = "ssh"
	}
	address := in.Address
	if address == "" {
		address = "seed.invalid:22"
	}
	return s.vault.CreateTarget(ctx, CreateTargetInput{
		WorkspaceID: in.WorkspaceID,
		Name:        name,
		Protocol:    protocol,
		Address:     address,
		Username:    in.Username,
		LeaseTTL:    defaultLeaseTTL,
		Secret:      in.Secret,
		Actor:       in.Actor,
	})
}
