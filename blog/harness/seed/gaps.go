package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/blog/harness/harnesskit"
	"github.com/kennguy3n/fishbone-access/internal/gateway"
	"github.com/kennguy3n/fishbone-access/internal/models"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
	"github.com/kennguy3n/fishbone-access/internal/services/pam"
)

// closeEvidenceGaps drives the three evidence trails the older seed left empty,
// using only production services so every row is a genuine, chained event:
//
//   - recordPrivilegedSession opens a real PAM session against a recorded
//     target, logs the operator's commands, persists the session recording to
//     the same replay store the live gateway writes, and anchors its digest in
//     the workspace hash chain. This is the half the series repeatedly flagged
//     as missing ("we govern the lease, not the session") — it lights up
//     CC6.7 / A.8.2 and PCI-DSS 10.2 with pam_sessions > 0.
//   - detectStandingAnomalies runs the same SoD anomaly sweep the scheduler
//     runs and evidences every standing toxic combination already held by the
//     workspace's live grants, lighting up CC7.3 with sod_anomalies > 0.
//   - exportEvidence exports an evidence pack (which verifies + snapshots the
//     hash chain) BEFORE the capture step reads coverage, so the resulting
//     evidence_exported record is in-chain and A.8.15 / PCI-DSS 10.2 read
//     covered rather than dropping out on an ordering quirk.
func (s *seeder) closeEvidenceGaps(c *harnesskit.Client, ws harnesskit.Workspace, workspaceID uuid.UUID, manualID string, disp *harnesskit.StepUpDispenser) string {
	sessionID := s.recordPrivilegedSession(ws, workspaceID)
	s.seedStandingConflict(c, ws, manualID)
	s.detectStandingAnomalies(workspaceID)
	s.exportEvidence(c, disp)
	return sessionID
}

// seedStandingConflict provisions a genuine standing separation-of-duties
// violation: one dedicated contractor subject is granted BOTH halves of the
// workspace's toxic-combination rule as live, approved contractor grants. The
// older seed only surfaced SoD in a pre-commit what-if (the reviewed grants were
// all revoked, so no subject ended up holding the combination) — here a real
// subject really does hold both active grants, which is what lets the standing
// detector that follows record a CC7.3 anomaly against live state rather than a
// hypothetical. Contractor approval is deliberately not SoD-gated (the pre-commit
// guardrail lives on the policy-grant path), which is exactly how toxic
// combinations accrete in the field — and why a standing sweep is needed.
func (s *seeder) seedStandingConflict(c *harnesskit.Client, ws harnesskit.Workspace, manualID string) {
	if manualID == "" || len(ws.SodRules) == 0 {
		return
	}
	connID, err := uuid.Parse(manualID)
	if err != nil {
		return
	}
	rule := ws.SodRules[0]
	sponsor := ws.OwnerSub()
	if len(ws.Contractors) > 0 && ws.Contractors[0].SponsorID != "" {
		sponsor = ws.Contractors[0].SponsorID
	}
	subject := "ext-dual-role@" + ws.Slug + ".example"
	halves := []struct{ resource, role string }{
		{rule.ResourceA, rule.RoleA},
		{rule.ResourceB, rule.RoleB},
	}
	for _, h := range halves {
		var created struct {
			Grant struct {
				ID string `json:"id"`
			} `json:"contractor_grant"`
		}
		body := map[string]any{
			"contractor_user_id": subject,
			"display_name":       "Dual-role contractor (SoD conflict)",
			"connector_id":       connID,
			"resource_ref":       h.resource,
			"role":               h.role,
			"sponsor_id":         sponsor,
			"justification":      "Standing SoD demo: same subject accrues both halves of a toxic combination.",
			"expires_at":         time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339),
		}
		if !c.JSON("POST", "/api/v1/contractor-grants", body, &created) || created.Grant.ID == "" {
			harnesskit.Logf("WARN %s: seed standing-conflict grant %s/%s", ws.Slug, h.resource, h.role)
			continue
		}
		c.JSON("POST", "/api/v1/contractor-grants/"+created.Grant.ID+"/approve", map[string]any{}, nil)
	}
}

// replayDir resolves the on-disk replay store the control plane serves from, so
// the seeded recording is retrievable over GET /pam/sessions/:id/replay exactly
// as a gateway-captured one would be.
func replayDir() string {
	if d := strings.TrimSpace(os.Getenv("PAM_REPLAY_DIR")); d != "" {
		return d
	}
	return "pam-replays"
}

// recordPrivilegedSession opens, drives and records one privileged session
// against a recorded target on the workspace, composing the production Vault /
// Broker / SessionManager so every event (pam.session.opened, pam.command,
// pam.session.recording, pam.session.closed) is identical to a gateway-emitted
// one. The recording bytes are written to the real replay store and their
// SHA-256 anchored in the chain, so the session is both monitored AND
// replayable — not merely leased. Idempotent: it is a no-op once the workspace
// already holds a recorded session.
func (s *seeder) recordPrivilegedSession(ws harnesskit.Workspace, workspaceID uuid.UUID) string {
	ctx := context.Background()

	var existing []models.PAMSession
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ?", workspaceID).Find(&existing).Error; err != nil {
		harnesskit.Logf("WARN %s: count pam sessions: %v", ws.Slug, err)
		return ""
	}
	if len(existing) > 0 {
		harnesskit.Logf("SKIP %s: privileged session already recorded (%d)", ws.Slug, len(existing))
		return existing[0].ID.String()
	}

	enc, err := access.CredentialEncryptorFromKey(os.Getenv("ACCESS_CREDENTIAL_DEK"))
	if err != nil {
		harnesskit.Logf("WARN %s: build pam encryptor: %v", ws.Slug, err)
		return ""
	}
	vault := pam.NewVault(s.db, enc, nil)
	broker := pam.NewBroker(s.db, vault, nil)
	sessions := pam.NewSessionManager(s.db, pam.NewCommandPolicyEvaluator(s.db, time.Minute), nil)

	target, commands := recordedSessionScenario(ws)
	created, err := vault.CreateTarget(ctx, pam.CreateTargetInput{
		WorkspaceID: workspaceID,
		Name:        target.Name,
		Protocol:    target.Protocol,
		Address:     target.Address,
		Username:    target.Username,
		LeaseTTL:    30 * time.Minute,
		Secret:      pam.Secret{Username: target.Username, Password: "demo-not-a-real-credential"},
		Actor:       ws.OwnerSub(),
	})
	if err != nil {
		harnesskit.Logf("WARN %s: create recorded target: %v", ws.Slug, err)
		return ""
	}

	rawToken, _, err := broker.MintConnectToken(ctx, pam.MintInput{
		WorkspaceID: workspaceID,
		TargetID:    created.ID,
		Subject:     ws.OwnerSub(),
		Actor:       ws.OwnerSub(),
	})
	if err != nil {
		harnesskit.Logf("WARN %s: mint connect token: %v", ws.Slug, err)
		return ""
	}
	leased, err := broker.RedeemConnectToken(ctx, rawToken, "blog-seed")
	if err != nil {
		harnesskit.Logf("WARN %s: redeem connect token: %v", ws.Slug, err)
		return ""
	}
	session := leased.Session

	// Record the session through the same IORecorder the live gateway uses, so
	// the persisted bytes are in the gateway's framed transcript format (the
	// replay API ParseReplay decodes input/output frames) rather than opaque
	// blob. Each command is an operator-input frame followed by its target-output
	// frame; LogCommand emits the chained pam.command evidence in parallel.
	rec := gateway.NewIORecorder(ctx, session.ID.String(), 0)
	rec.Record(gateway.DirControl, []byte(fmt.Sprintf("recorded privileged session %s@%s", target.Username, target.Address)))
	for _, cmd := range commands {
		if _, err := sessions.LogCommand(ctx, session, cmd.in); err != nil {
			_ = sessions.CloseSession(ctx, workspaceID, session.ID)
			harnesskit.Logf("WARN %s: log command: %v", ws.Slug, err)
			return ""
		}
		rec.Record(gateway.DirInput, []byte(cmd.in+"\r\n"))
		rec.Record(gateway.DirOutput, []byte(cmd.out+"\r\n"))
	}

	store, err := gateway.NewFilesystemReplayStore(replayDir())
	if err != nil {
		harnesskit.Logf("WARN %s: open replay store: %v", ws.Slug, err)
		return ""
	}
	if err := rec.Flush(ctx, store); err != nil {
		harnesskit.Logf("WARN %s: persist replay: %v", ws.Slug, err)
		return ""
	}
	rc := rec.Recording()
	if err := sessions.RecordRecording(ctx, session, pam.RecordingRef{
		Key:       rc.Key,
		SHA256:    rc.SHA256,
		Bytes:     rc.Bytes,
		Truncated: rc.Truncated,
	}); err != nil {
		harnesskit.Logf("WARN %s: anchor recording: %v", ws.Slug, err)
		return ""
	}
	if err := sessions.CloseSession(ctx, workspaceID, session.ID); err != nil {
		harnesskit.Logf("WARN %s: close session: %v", ws.Slug, err)
		return ""
	}
	harnesskit.Logf("OK   %s: recorded privileged session %s (%d commands, %d-byte framed replay)", ws.Slug, session.ID, len(commands), rc.Bytes)
	return session.ID.String()
}

// detectStandingAnomalies runs the production SoD anomaly sweep for the
// workspace and evidences every standing toxic combination held by its live
// grants. The seeded request/grant set already hands the workspace owner both
// halves of the workspace's SoD rule, so this surfaces a real standing
// violation (not a what-if), recording the CC7.3 detection + auto-disposition
// evidence the older seed never produced.
func (s *seeder) detectStandingAnomalies(workspaceID uuid.UUID) {
	n, err := lifecycle.NewAnomalyDetector(s.db).DetectAndRecord(context.Background(), workspaceID)
	if err != nil {
		harnesskit.Logf("WARN detect standing anomalies: %v", err)
		return
	}
	harnesskit.Logf("OK   standing SoD anomalies detected + dispositioned: %d", n)
}

// exportEvidence exports an evidence pack over the real, step-up-gated export
// route. The export verifies and snapshots the workspace hash chain and appends
// an evidence_exported record IN-CHAIN; doing it during seed (before capture
// reads coverage) is what keeps A.8.15 ("tamper-evident logging") and the
// export half of PCI-DSS 10.2 covered. SOC 2 is a valid framework for every
// workspace and the record's kind — not its framework — is what the coverage
// map keys on.
func (s *seeder) exportEvidence(c *harnesskit.Client, disp *harnesskit.StepUpDispenser) {
	status, _, err := c.Request("POST", "/api/v1/compliance/export",
		map[string]any{"framework": "SOC 2"},
		map[string]string{harnesskit.StepUpHeader: disp.Next()})
	if err != nil {
		harnesskit.Logf("WARN evidence export: %v", err)
		return
	}
	if status < 200 || status >= 300 {
		harnesskit.Logf("WARN evidence export: HTTP %d", status)
		return
	}
	harnesskit.Logf("OK   evidence pack exported (evidence_exported anchored in-chain)")
}

// recordedCommand is one logged command in a seeded session plus the synthetic
// terminal output captured for its replay.
type recordedCommand struct {
	in  string
	out string
}

// recordedTarget describes the recorded-session host created for a workspace.
type recordedTarget struct {
	Name     string
	Protocol string
	Address  string
	Username string
}

// recordedSessionScenario returns a scenario-flavoured recorded-session target
// and the privileged commands the operator runs through it, so each workspace's
// CC6.7 / A.8.2 evidence reads like a real operational session rather than a
// placeholder.
func recordedSessionScenario(ws harnesskit.Workspace) (recordedTarget, []recordedCommand) {
	switch ws.Slug {
	case "sg-acme-payments":
		return recordedTarget{"Ledger bastion (recorded session)", "ssh", "ledger-bastion.acme-pay.internal:22", "ops"},
			[]recordedCommand{
				{"whoami", "ops"},
				{"sudo systemctl status ledger-postgres", "● ledger-postgres.service - active (running)"},
				{"psql -At -c \"select count(*) from postings where settled_at is null\"", "0"},
				{"exit", "logout"},
			}
	case "us-globex-health":
		return recordedTarget{"EHR bastion (recorded session)", "ssh", "ehr-bastion.globex.internal:22", "ehr-ops"},
			[]recordedCommand{
				{"whoami", "ehr-ops"},
				{"sudo systemctl status epic-interconnect", "● epic-interconnect.service - active (running)"},
				{"tail -n 1 /var/log/epic/audit.log", "phi access via authorised JIT lease"},
				{"exit", "logout"},
			}
	case "de-initech-retail":
		return recordedTarget{"POS bastion (recorded session)", "ssh", "pos-bastion.initech.internal:22", "pos-ops"},
			[]recordedCommand{
				{"whoami", "pos-ops"},
				{"sudo systemctl status sap-pos", "● sap-pos.service - active (running)"},
				{"mysql -N -e \"select count(*) from pos.terminals where status='online'\"", "248"},
				{"exit", "logout"},
			}
	case "vn-umbrella-logistics":
		return recordedTarget{"WMS bastion (recorded session)", "ssh", "wms-bastion.umbrella.internal:22", "wms-ops"},
			[]recordedCommand{
				{"whoami", "wms-ops"},
				{"sudo systemctl status wms-core", "● wms-core.service - active (running)"},
				{"tail -n 1 /var/log/wms/dispatch.log", "dispatch queue drained"},
				{"exit", "logout"},
			}
	case "ae-northwind-finance":
		return recordedTarget{"T24 bastion (recorded session)", "ssh", "t24-bastion.northwind.internal:22", "t24-ops"},
			[]recordedCommand{
				{"whoami", "t24-ops"},
				{"sudo systemctl status t24-core", "● t24-core.service - active (running)"},
				{"tail -n 1 /var/log/t24/eod.log", "end-of-day batch complete"},
				{"exit", "logout"},
			}
	default: // au-contoso-saas
		return recordedTarget{"Prod bastion (recorded session)", "ssh", "prod-bastion.contoso.internal:22", "sre"},
			[]recordedCommand{
				{"whoami", "sre"},
				{"sudo systemctl status app-prod", "● app-prod.service - active (running)"},
				{"kubectl get deploy -n prod app -o jsonpath='{.status.readyReplicas}'", "6"},
				{"exit", "logout"},
			}
	}
}
