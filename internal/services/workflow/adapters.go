package workflow

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/services/lifecycle"
)

// This file adapts the lifecycle services to the narrow interfaces the executor
// drives (Granter/Approver/Reviewer/Notifier/KillSwitch/Auditor). Keeping the
// adapters here — behind the exported BuildStepDeps — means both the HTTP
// handlers (manual "run now") and the access-workflow-engine job build their
// dependencies the same way, and the executor itself stays free of any concrete
// service or tenant plumbing (so its unit tests use fakes).

// StepServices is the set of lifecycle services the step adapters need. The
// caller (handler or engine wiring) constructs these once off the shared DB
// pool and passes them to BuildStepDeps per run.
type StepServices struct {
	Requests *lifecycle.AccessRequestService
	Prov     *lifecycle.AccessProvisioningService
	Reviews  *lifecycle.ReviewService
	JML      *lifecycle.JMLService
}

// BuildStepDeps wires the executor's dependencies for one run in workspace ws,
// performed by actor. The adapters are bound to that workspace + actor so the
// executor never sees tenant or identity plumbing.
func BuildStepDeps(db *gorm.DB, svcs StepServices, ws uuid.UUID, actor string) StepDeps {
	return StepDeps{
		Grants:     grantAdapter{requests: svcs.Requests, prov: svcs.Prov, ws: ws},
		Approvals:  approvalAdapter{requests: svcs.Requests, ws: ws},
		Reviews:    reviewAdapter{reviews: svcs.Reviews, ws: ws},
		Notifier:   notifyAdapter{db: db, ws: ws},
		KillSwitch: killSwitchAdapter{jml: svcs.JML, ws: ws},
		Audit:      auditAdapter{db: db, ws: ws, actor: actor},
	}
}

// grantAdapter provisions access for grant_role / provision_connector steps by
// creating an access request for the subject and provisioning it immediately
// (the workflow itself is the authorization decision, so no separate human
// approval is required — request_approval is the gated variant).
type grantAdapter struct {
	requests *lifecycle.AccessRequestService
	prov     *lifecycle.AccessProvisioningService
	ws       uuid.UUID
}

func (a grantAdapter) GrantRole(ctx context.Context, in GrantInput, actor string) (string, error) {
	connID, err := uuid.Parse(in.ConnectorID)
	if err != nil {
		return "", err
	}
	req, err := a.requests.CreateRequest(ctx, lifecycle.CreateAccessRequestInput{
		WorkspaceID:   a.ws,
		RequesterID:   actor,
		TargetUserID:  in.Subject.ExternalID,
		ConnectorID:   &connID,
		ResourceRef:   in.ResourceRef,
		Role:          in.Role,
		Justification: "JML workflow automated grant",
	})
	if err != nil {
		return "", err
	}
	// CreateRequest leaves the request in StateRequested, but Provision only
	// accepts an approved request (the FSM forbids requested → provisioning).
	// The workflow itself IS the authorization decision (request_approval is the
	// human-gated variant), so auto-approve here — mirroring the JML joiner path
	// (lifecycle.WorkflowService auto-approve lane), which approves before
	// provisioning. Return the request id on failure so an operator can locate
	// the half-completed request.
	if err := a.requests.ApproveRequest(ctx, a.ws, req.ID, actor, "JML workflow automated grant"); err != nil {
		return req.ID.String(), err
	}
	grant, err := a.prov.Provision(ctx, a.ws, req.ID, actor)
	if err != nil {
		// Surface the request id so an operator can find the half-completed
		// request even though provisioning failed.
		return req.ID.String(), err
	}
	return grant.ID.String(), nil
}

// approvalAdapter opens an access request for the subject and leaves it pending
// for a human (the approver_role) to approve via the existing
// /access-requests/:id/approve endpoint. It does NOT provision — that is the
// human gate.
type approvalAdapter struct {
	requests *lifecycle.AccessRequestService
	ws       uuid.UUID
}

func (a approvalAdapter) RequestApproval(ctx context.Context, in GrantInput, approverRole, actor string) (string, error) {
	connID, err := uuid.Parse(in.ConnectorID)
	if err != nil {
		return "", err
	}
	req, err := a.requests.CreateRequest(ctx, lifecycle.CreateAccessRequestInput{
		WorkspaceID:   a.ws,
		RequesterID:   actor,
		TargetUserID:  in.Subject.ExternalID,
		ConnectorID:   &connID,
		ResourceRef:   in.ResourceRef,
		Role:          in.Role,
		Justification: "JML workflow approval gate; approver role: " + approverRole,
	})
	if err != nil {
		return "", err
	}
	return req.ID.String(), nil
}

// reviewAdapter starts an access-review campaign for start_access_review steps.
type reviewAdapter struct {
	reviews *lifecycle.ReviewService
	ws      uuid.UUID
}

func (a reviewAdapter) StartReview(ctx context.Context, name, actor string) (string, error) {
	rev, _, err := a.reviews.StartCampaign(ctx, a.ws, name, actor)
	if err != nil {
		return "", err
	}
	return rev.ID.String(), nil
}

// notifyAdapter records a notification intent on the per-workspace audit hash
// chain. The audit chain is the platform's durable, tamper-evident event sink:
// there is no external email/Slack connector yet, so a notify step persists a
// real, queryable record (surfaced in the console audit view) rather than
// performing fake delivery. When an outbound channel is added this adapter is
// the single integration point.
type notifyAdapter struct {
	db *gorm.DB
	ws uuid.UUID
}

func (a notifyAdapter) Notify(ctx context.Context, subject Subject, channel, message, actor string) (string, error) {
	meta, _ := json.Marshal(map[string]string{
		"channel": channel,
		"message": message,
		"subject": subject.ExternalID,
	})
	if err := lifecycle.AppendAudit(ctx, a.db, time.Now(), lifecycle.AuditInput{
		WorkspaceID: a.ws,
		Actor:       actor,
		Action:      "workflow.notify." + channel,
		TargetRef:   subject.ExternalID,
		Metadata:    datatypes.JSON(meta),
	}); err != nil {
		return "", err
	}
	return channel, nil
}

// killSwitchAdapter runs the lifecycle six-layer leaver kill switch for
// run_kill_switch steps, mapping the lifecycle result to the workflow package's
// decoupled layer type.
type killSwitchAdapter struct {
	jml *lifecycle.JMLService
	ws  uuid.UUID
}

func (a killSwitchAdapter) RunKillSwitch(ctx context.Context, subjectExternalID, actor string) ([]KillSwitchLayer, bool, error) {
	res, err := a.jml.RunKillSwitch(ctx, a.ws, subjectExternalID, actor)
	layers := make([]KillSwitchLayer, 0)
	if res != nil {
		for _, l := range res.Layers {
			layers = append(layers, KillSwitchLayer{Layer: l.Layer, Status: l.Status, Detail: l.Detail})
		}
		return layers, res.Errored, err
	}
	return layers, err != nil, err
}

// auditAdapter appends one entry per executed step to the per-workspace audit
// hash chain, bound to the run's workspace + actor.
type auditAdapter struct {
	db    *gorm.DB
	ws    uuid.UUID
	actor string
}

func (a auditAdapter) Append(ctx context.Context, action, targetRef, detail string) error {
	var meta datatypes.JSON
	if detail != "" {
		if b, err := json.Marshal(map[string]string{"detail": detail}); err == nil {
			meta = datatypes.JSON(b)
		}
	}
	return lifecycle.AppendAudit(ctx, a.db, time.Now(), lifecycle.AuditInput{
		WorkspaceID: a.ws,
		Actor:       a.actor,
		Action:      action,
		TargetRef:   targetRef,
		Metadata:    meta,
	})
}
