package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// killSwitchLayerOrder mirrors lifecycle.HandleLeaver's execution order. The
// dry-run planner lists these so the admin sees exactly what an emergency
// offboard WOULD do without running it. It is a presentation copy only — the
// live cascade order is owned by the lifecycle kill switch.
var killSwitchLayerOrder = []string{
	"grant_revoke", "team_remove", "iam_core_disable",
	"session_revoke", "scim_deprovision", "identity_disable",
}

// KillSwitchLayer is one kill-switch layer outcome surfaced in a workflow run
// (decoupled mirror of lifecycle.KillSwitchLayerResult so the workflow package
// does not depend on lifecycle internals).
type KillSwitchLayer struct {
	Layer  string `json:"layer"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// StepOutcome is the recorded result of one step, for both dry-run (Status
// "planned") and live runs. Layers is populated only for a run_kill_switch
// step.
type StepOutcome struct {
	Index  int               `json:"index"`
	Type   string            `json:"type"`
	Name   string            `json:"name,omitempty"`
	Status string            `json:"status"`
	Detail string            `json:"detail,omitempty"`
	Ref    string            `json:"ref,omitempty"`
	Layers []KillSwitchLayer `json:"layers,omitempty"`
}

// RunResult is the full outcome of an Execute call. For a dry-run it is the
// "what would happen" plan returned to the simulate panel and cached on the
// draft; for a live run it is persisted as a models.WorkflowRun.
type RunResult struct {
	Mode    string        `json:"mode"`
	Matched bool          `json:"matched"`
	Status  string        `json:"status"`
	Subject Subject       `json:"subject"`
	Steps   []StepOutcome `json:"steps"`
	RunID   *uuid.UUID    `json:"run_id,omitempty"`
}

// GrantInput is the resolved provisioning request for a grant_role /
// provision_connector step.
type GrantInput struct {
	Subject     Subject
	ConnectorID string
	ResourceRef string
	Role        string
}

// The executor's side-effecting dependencies. Each is an interface so the
// executor is unit-tested with fakes and the workflow package never hard-links
// the lifecycle services; the handler/engine layers supply thin adapters. A nil
// dependency makes its step report "skipped" with a reason — except the leaver
// kill switch, whose absence on a leaver run is reported "failed" (fail-closed:
// an emergency offboard must never silently no-op).
type (
	Granter interface {
		GrantRole(ctx context.Context, in GrantInput, actor string) (ref string, err error)
	}
	Approver interface {
		RequestApproval(ctx context.Context, in GrantInput, approverRole, actor string) (ref string, err error)
	}
	Reviewer interface {
		StartReview(ctx context.Context, name, actor string) (ref string, err error)
	}
	Notifier interface {
		Notify(ctx context.Context, subject Subject, channel, message, actor string) (ref string, err error)
	}
	KillSwitch interface {
		RunKillSwitch(ctx context.Context, subjectExternalID, actor string) (layers []KillSwitchLayer, errored bool, err error)
	}
	// Auditor appends one entry to the per-workspace audit hash chain. The
	// adapter binds the workspace + actor; the executor supplies action/target.
	Auditor interface {
		Append(ctx context.Context, action, targetRef, detail string) error
	}
)

// StepDeps bundles the executor's dependencies for one run. The handler/engine
// builds these bound to the workspace + actor for each Execute call.
type StepDeps struct {
	Grants     Granter
	Approvals  Approver
	Reviews    Reviewer
	Notifier   Notifier
	KillSwitch KillSwitch
	Audit      Auditor
}

// Executor runs a parsed workflow document for one subject. It is stateless
// apart from the DB handle (used only to persist live runs) and the clock.
type Executor struct {
	db  *gorm.DB
	now func() time.Time
}

// NewExecutor returns an executor. db may be nil for a pure dry-run executor
// (dry-runs never persist), but a live Execute with a nil db returns an error
// rather than silently dropping the run record.
func NewExecutor(db *gorm.DB) *Executor {
	return &Executor{db: db, now: time.Now}
}

// SetClock overrides the time source (tests).
func (e *Executor) SetClock(now func() time.Time) {
	if now != nil {
		e.now = now
	}
}

// RunParams is the input to Execute.
type RunParams struct {
	WorkspaceID uuid.UUID
	Workflow    *models.Workflow
	Doc         Doc
	Subject     Subject
	Mode        string
	Actor       string
	Deps        StepDeps
}

// Execute runs the workflow for the subject. In ModeDryRun it performs NO
// side effects and NO audit writes: it returns the ordered plan of what each
// step WOULD do. In ModeLive it drives each step's dependency, appends an audit
// entry per executed step, and persists a models.WorkflowRun. A failed step is
// recorded and the run CONTINUES to the remaining steps (resilient, mirroring
// the kill switch) rather than aborting and leaving later steps silently
// un-run; the aggregate status reflects any failure.
func (e *Executor) Execute(ctx context.Context, p RunParams) (*RunResult, error) {
	if p.Subject.ExternalID == "" {
		return nil, fmt.Errorf("%w: a subject external id is required to run a workflow", ErrValidation)
	}
	mode := p.Mode
	if mode != ModeDryRun && mode != ModeLive {
		return nil, fmt.Errorf("%w: run mode must be dry_run or live, got %q", ErrValidation, mode)
	}

	started := e.now()
	result := &RunResult{Mode: mode, Subject: p.Subject, Matched: p.Doc.Matches(p.Subject)}

	if !result.Matched {
		result.Status = StatusSkipped
		result.Steps = []StepOutcome{{
			Index:  0,
			Type:   "conditions",
			Status: StatusSkipped,
			Detail: "subject does not match the workflow conditions; no steps run",
		}}
	} else if mode == ModeDryRun {
		result.Steps = e.plan(p.Doc)
		result.Status = StatusPlanned
	} else {
		result.Steps = e.runLive(ctx, p)
		result.Status = aggregateStatus(result.Steps)
	}

	if mode == ModeLive {
		runID, err := e.persistRun(ctx, p, result, started)
		if err != nil {
			return nil, err
		}
		result.RunID = runID
	}
	return result, nil
}

// plan produces the dry-run outcome for each step: a human-readable description
// of what WOULD happen, with no dependency calls.
func (e *Executor) plan(doc Doc) []StepOutcome {
	out := make([]StepOutcome, 0, len(doc.Steps))
	for i, s := range doc.Steps {
		o := StepOutcome{Index: i, Type: s.Type, Name: s.Name, Status: StatusPlanned}
		switch s.Type {
		case StepGrantRole, StepProvisionConnector:
			o.Detail = fmt.Sprintf("would grant role %q on %q", s.Role, s.ResourceRef)
			if s.ConnectorID != "" {
				o.Detail += fmt.Sprintf(" via connector %s", s.ConnectorID)
			}
		case StepRequestApproval:
			o.Detail = fmt.Sprintf("would open an approval request for %q", s.ApproverRole)
		case StepNotify:
			o.Detail = fmt.Sprintf("would notify via %q", s.Channel)
		case StepStartAccessReview:
			o.Detail = fmt.Sprintf("would start access review %q", s.ReviewName)
		case StepRunKillSwitch:
			o.Detail = "would run the six-layer leaver kill switch"
			o.Layers = make([]KillSwitchLayer, 0, len(killSwitchLayerOrder))
			for _, l := range killSwitchLayerOrder {
				o.Layers = append(o.Layers, KillSwitchLayer{Layer: l, Status: StatusPlanned})
			}
		}
		out = append(out, o)
	}
	return out
}

// runLive executes each step in order, recording its outcome and appending an
// audit entry per step.
func (e *Executor) runLive(ctx context.Context, p RunParams) []StepOutcome {
	out := make([]StepOutcome, 0, len(p.Doc.Steps))
	for i, s := range p.Doc.Steps {
		o := e.runStep(ctx, p, i, s)
		e.audit(ctx, p, o)
		out = append(out, o)
	}
	return out
}

func (e *Executor) runStep(ctx context.Context, p RunParams, idx int, s Step) StepOutcome {
	o := StepOutcome{Index: idx, Type: s.Type, Name: s.Name}
	switch s.Type {
	case StepGrantRole, StepProvisionConnector:
		if p.Deps.Grants == nil {
			return skip(o, "no provisioning dependency wired")
		}
		ref, err := p.Deps.Grants.GrantRole(ctx, GrantInput{
			Subject:     p.Subject,
			ConnectorID: s.ConnectorID,
			ResourceRef: s.ResourceRef,
			Role:        s.Role,
		}, p.Actor)
		return done(o, ref, err, fmt.Sprintf("granted %q on %q", s.Role, s.ResourceRef))
	case StepRequestApproval:
		if p.Deps.Approvals == nil {
			return skip(o, "no approval dependency wired")
		}
		ref, err := p.Deps.Approvals.RequestApproval(ctx, GrantInput{
			Subject:     p.Subject,
			ConnectorID: s.ConnectorID,
			ResourceRef: s.ResourceRef,
			Role:        s.Role,
		}, s.ApproverRole, p.Actor)
		return done(o, ref, err, fmt.Sprintf("opened approval for %q", s.ApproverRole))
	case StepNotify:
		if p.Deps.Notifier == nil {
			return skip(o, "no notifier dependency wired")
		}
		ref, err := p.Deps.Notifier.Notify(ctx, p.Subject, s.Channel, s.Message, p.Actor)
		return done(o, ref, err, fmt.Sprintf("notified via %q", s.Channel))
	case StepStartAccessReview:
		if p.Deps.Reviews == nil {
			return skip(o, "no review dependency wired")
		}
		ref, err := p.Deps.Reviews.StartReview(ctx, s.ReviewName, p.Actor)
		return done(o, ref, err, fmt.Sprintf("started review %q", s.ReviewName))
	case StepRunKillSwitch:
		if p.Deps.KillSwitch == nil {
			// Fail-closed: a leaver workflow whose kill switch cannot run must
			// not look successful.
			o.Status = StatusFailed
			o.Detail = "no kill-switch dependency wired"
			return o
		}
		layers, errored, err := p.Deps.KillSwitch.RunKillSwitch(ctx, p.Subject.ExternalID, p.Actor)
		o.Layers = layers
		if err != nil && len(layers) == 0 {
			o.Status = StatusFailed
			o.Detail = err.Error()
			return o
		}
		if errored {
			o.Status = StatusFailed
			o.Detail = "one or more kill-switch layers failed"
			return o
		}
		o.Status = StatusDone
		o.Detail = "six-layer kill switch completed"
		return o
	default:
		o.Status = StatusFailed
		o.Detail = fmt.Sprintf("unknown step type %q", s.Type)
		return o
	}
}

func (e *Executor) audit(ctx context.Context, p RunParams, o StepOutcome) {
	if p.Deps.Audit == nil {
		return
	}
	action := fmt.Sprintf("workflow.run.step.%s.%s", o.Type, o.Status)
	detail := o.Detail
	if o.Ref != "" {
		detail = o.Ref + ": " + detail
	}
	// An audit-append failure on a step is a compliance gap, but the step's
	// real side effect already happened; annotate the outcome rather than
	// pretending the step failed. The run-level persistence still records it.
	if err := p.Deps.Audit.Append(ctx, action, p.Subject.ExternalID, detail); err != nil {
		o.Detail += "; audit append failed: " + err.Error()
	}
}

func (e *Executor) persistRun(ctx context.Context, p RunParams, r *RunResult, started time.Time) (*uuid.UUID, error) {
	if e.db == nil {
		return nil, fmt.Errorf("workflow: live run requires a database handle")
	}
	stepsJSON, err := json.Marshal(r.Steps)
	if err != nil {
		return nil, fmt.Errorf("workflow: marshal run steps: %w", err)
	}
	completed := e.now()
	var workflowID uuid.UUID
	version := 1
	if p.Workflow != nil {
		workflowID = p.Workflow.ID
		version = p.Workflow.Version
	}
	run := &models.WorkflowRun{
		WorkspaceID:       p.WorkspaceID,
		WorkflowID:        workflowID,
		WorkflowVersion:   version,
		Trigger:           p.Doc.Trigger,
		SubjectExternalID: p.Subject.ExternalID,
		Mode:              ModeLive,
		Status:            r.Status,
		Steps:             datatypes.JSON(stepsJSON),
		StartedAt:         started,
		CompletedAt:       &completed,
	}
	run.CreatedAt = completed
	run.UpdatedAt = completed
	if err := e.db.WithContext(ctx).Create(run).Error; err != nil {
		return nil, fmt.Errorf("workflow: persist run: %w", err)
	}
	return &run.ID, nil
}

func skip(o StepOutcome, detail string) StepOutcome {
	o.Status = StatusSkipped
	o.Detail = detail
	return o
}

func done(o StepOutcome, ref string, err error, detail string) StepOutcome {
	o.Ref = ref
	if err != nil {
		o.Status = StatusFailed
		o.Detail = err.Error()
		return o
	}
	o.Status = StatusDone
	o.Detail = detail
	return o
}

// aggregateStatus reduces per-step outcomes to a run status: succeeded when no
// step failed, failed when every actioned step failed, partial otherwise.
func aggregateStatus(steps []StepOutcome) string {
	var failed, done int
	for _, s := range steps {
		switch s.Status {
		case StatusFailed:
			failed++
		case StatusDone:
			done++
		}
	}
	switch {
	case failed == 0:
		return StatusSucceeded
	case done == 0:
		return StatusFailed
	default:
		return StatusPartial
	}
}
