// Package workflow implements the no-code Joiner/Mover/Leaver workflow builder:
// a declarative, versioned workflow document (trigger + conditions + ordered
// steps) with the same draft → simulate → publish lifecycle as the access
// policy engine, plus an executor that runs a published workflow for a single
// subject identity (live) or shows what WOULD happen without side effects
// (dry-run / simulate).
//
// The document is deliberately small and strongly typed so a non-technical SME
// admin assembles it from a form in the console (ui/) rather than writing JSON,
// and so a malformed workflow can never be simulated, published, or executed.
package workflow

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
)

// Workflow lifecycle states. A workflow is born "draft", may be "published"
// (the only state the engine executes), and may later be "archived". Drafts and
// archived workflows never run.
const (
	StateDraft     = "draft"
	StatePublished = "published"
	StateArchived  = "archived"
)

// Workflow kinds: the JML lane a workflow automates. The kind gates which steps
// are allowed (the destructive kill switch is leaver-only).
const (
	KindJoiner = "joiner"
	KindMover  = "mover"
	KindLeaver = "leaver"
)

// Workflow triggers: what fires a published workflow.
const (
	TriggerIdentityEvent = "identity_event"
	TriggerSchedule      = "schedule"
	TriggerManual        = "manual"
)

// Step types the executor understands. Each maps to a real lifecycle action;
// there are no placeholder/no-op step types.
const (
	StepGrantRole         = "grant_role"
	StepProvisionConnector = "provision_connector"
	StepRequestApproval   = "request_approval"
	StepNotify            = "notify"
	StepStartAccessReview = "start_access_review"
	StepRunKillSwitch     = "run_kill_switch"
)

// Condition operators for matching a subject's attributes.
const (
	OpEquals      = "eq"
	OpNotEquals   = "neq"
	OpIn          = "in"
	OpContains    = "contains"
	OpNotContains = "not_contains"
)

// Run modes.
const (
	ModeDryRun = "dry_run"
	ModeLive   = "live"
)

// Run / step outcome statuses.
const (
	StatusPlanned   = "planned" // dry-run: what WOULD happen
	StatusDone      = "done"
	StatusSkipped   = "skipped"
	StatusFailed    = "failed"
	StatusSucceeded = "succeeded" // aggregate run status
	StatusPartial   = "partial"   // aggregate: at least one step failed/skipped
)

// Condition is one attribute predicate evaluated against the subject identity.
// The cartesian set of conditions is ANDed: every condition must hold for the
// workflow to act on the subject.
type Condition struct {
	Attribute string   `json:"attribute"`
	Operator  string   `json:"operator"`
	Values    []string `json:"values"`
}

// Step is one ordered action in a workflow. The fields are a flat, optional
// superset across step types (strongly typed, no free-form maps) so the builder
// form binds directly to it; Validate enforces the per-type required fields.
type Step struct {
	Type string `json:"type"`
	// Name is an optional human label shown in the builder and the run audit.
	Name string `json:"name,omitempty"`

	// grant_role / provision_connector
	ConnectorID string `json:"connector_id,omitempty"`
	ResourceRef string `json:"resource_ref,omitempty"`
	Role        string `json:"role,omitempty"`

	// request_approval
	ApproverRole string `json:"approver_role,omitempty"`

	// notify
	Channel string `json:"channel,omitempty"`
	Message string `json:"message,omitempty"`

	// start_access_review
	ReviewName string `json:"review_name,omitempty"`
}

// Doc is the decoded form of models.Workflow.Definition: a declarative JML
// automation. Kind selects the lane, Trigger selects what fires it, Conditions
// gate which identities it acts on, and Steps is the ordered pipeline.
type Doc struct {
	Kind       string      `json:"kind"`
	Trigger    string      `json:"trigger"`
	Conditions []Condition `json:"conditions,omitempty"`
	Steps      []Step      `json:"steps"`
}

// validKinds / validTriggers / validStepTypes / validOperators back the
// fail-closed validation: an unknown value is rejected rather than ignored.
var (
	validKinds     = map[string]struct{}{KindJoiner: {}, KindMover: {}, KindLeaver: {}}
	validTriggers  = map[string]struct{}{TriggerIdentityEvent: {}, TriggerSchedule: {}, TriggerManual: {}}
	validStepTypes = map[string]struct{}{
		StepGrantRole: {}, StepProvisionConnector: {}, StepRequestApproval: {},
		StepNotify: {}, StepStartAccessReview: {}, StepRunKillSwitch: {},
	}
	validOperators = map[string]struct{}{
		OpEquals: {}, OpNotEquals: {}, OpIn: {}, OpContains: {}, OpNotContains: {},
	}
)

// ParseDoc decodes and validates a raw workflow document. It rejects unknown
// fields so a typo (e.g. "steps" misspelled) surfaces as an error rather than a
// silently empty pipeline, and runs Validate so a malformed workflow can never
// enter the system.
func ParseDoc(raw []byte) (Doc, error) {
	var doc Doc
	if len(raw) == 0 {
		return doc, fmt.Errorf("%w: workflow definition is empty", ErrValidation)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return doc, fmt.Errorf("%w: workflow definition: %v", ErrValidation, err)
	}
	doc.normalize()
	if err := doc.Validate(); err != nil {
		return doc, err
	}
	return doc, nil
}

// normalize lowercases/trims the enum-like fields so validation and execution
// are case-insensitive and whitespace-tolerant for the values the builder emits.
func (d *Doc) normalize() {
	d.Kind = strings.ToLower(strings.TrimSpace(d.Kind))
	d.Trigger = strings.ToLower(strings.TrimSpace(d.Trigger))
	for i := range d.Conditions {
		d.Conditions[i].Attribute = strings.TrimSpace(d.Conditions[i].Attribute)
		d.Conditions[i].Operator = strings.ToLower(strings.TrimSpace(d.Conditions[i].Operator))
		d.Conditions[i].Values = normalizeSet(d.Conditions[i].Values)
	}
	for i := range d.Steps {
		d.Steps[i].Type = strings.ToLower(strings.TrimSpace(d.Steps[i].Type))
		d.Steps[i].ConnectorID = strings.TrimSpace(d.Steps[i].ConnectorID)
		d.Steps[i].ResourceRef = strings.TrimSpace(d.Steps[i].ResourceRef)
		d.Steps[i].Role = strings.TrimSpace(d.Steps[i].Role)
		d.Steps[i].ApproverRole = strings.TrimSpace(d.Steps[i].ApproverRole)
		d.Steps[i].Channel = strings.TrimSpace(d.Steps[i].Channel)
		d.Steps[i].ReviewName = strings.TrimSpace(d.Steps[i].ReviewName)
	}
}

// Validate enforces the workflow document's invariants. It is fail-closed: an
// unknown kind/trigger/step/operator, an empty pipeline, or a step missing its
// required fields is rejected. The destructive kill switch is leaver-only so it
// can never be wired into a joiner/mover automation.
func (d Doc) Validate() error {
	if _, ok := validKinds[d.Kind]; !ok {
		return fmt.Errorf("%w: workflow kind must be one of joiner/mover/leaver, got %q", ErrValidation, d.Kind)
	}
	if _, ok := validTriggers[d.Trigger]; !ok {
		return fmt.Errorf("%w: workflow trigger must be one of identity_event/schedule/manual, got %q", ErrValidation, d.Trigger)
	}
	for i, c := range d.Conditions {
		if c.Attribute == "" {
			return fmt.Errorf("%w: condition %d is missing an attribute", ErrValidation, i+1)
		}
		if _, ok := validOperators[c.Operator]; !ok {
			return fmt.Errorf("%w: condition %d has an unknown operator %q", ErrValidation, i+1, c.Operator)
		}
		if len(c.Values) == 0 {
			return fmt.Errorf("%w: condition %d (%s) needs at least one value", ErrValidation, i+1, c.Attribute)
		}
	}
	if len(d.Steps) == 0 {
		return fmt.Errorf("%w: workflow must have at least one step", ErrValidation)
	}
	for i, s := range d.Steps {
		if err := s.validate(d.Kind); err != nil {
			return fmt.Errorf("%w (step %d)", err, i+1)
		}
	}
	return nil
}

func (s Step) validate(kind string) error {
	if _, ok := validStepTypes[s.Type]; !ok {
		return fmt.Errorf("%w: unknown step type %q", ErrValidation, s.Type)
	}
	switch s.Type {
	case StepGrantRole, StepProvisionConnector:
		// Provisioning needs a concrete upstream target: connector + resource +
		// role. Validating up front means a published workflow never fails a
		// live grant for a missing field.
		if err := requireConnectorTarget(s); err != nil {
			return err
		}
	case StepRequestApproval:
		// An approval-gated grant is a normal access request that stops in the
		// pending state for a human to approve, so it needs the same target plus
		// the approver role to route to.
		if s.ApproverRole == "" {
			return fmt.Errorf("%w: request_approval step requires an approver_role", ErrValidation)
		}
		if err := requireConnectorTarget(s); err != nil {
			return err
		}
	case StepNotify:
		if s.Channel == "" {
			return fmt.Errorf("%w: notify step requires a channel", ErrValidation)
		}
	case StepStartAccessReview:
		if s.ReviewName == "" {
			return fmt.Errorf("%w: start_access_review step requires a review_name", ErrValidation)
		}
	case StepRunKillSwitch:
		// The six-layer kill switch is irreversible offboarding; it is only
		// valid on a leaver workflow so it can never be attached to a joiner or
		// mover automation by mistake.
		if kind != KindLeaver {
			return fmt.Errorf("%w: run_kill_switch is only allowed on a leaver workflow", ErrValidation)
		}
	}
	return nil
}

// requireConnectorTarget validates the connector + resource + role triple that
// every provisioning-style step (grant_role / provision_connector /
// request_approval) needs, including that connector_id is a real UUID so the
// adapter never has to parse-and-fail at run time.
func requireConnectorTarget(s Step) error {
	if s.ConnectorID == "" {
		return fmt.Errorf("%w: %s step requires a connector_id", ErrValidation, s.Type)
	}
	if _, err := uuid.Parse(s.ConnectorID); err != nil {
		return fmt.Errorf("%w: %s step connector_id %q is not a valid id", ErrValidation, s.Type, s.ConnectorID)
	}
	if s.ResourceRef == "" {
		return fmt.Errorf("%w: %s step requires a resource_ref", ErrValidation, s.Type)
	}
	if s.Role == "" {
		return fmt.Errorf("%w: %s step requires a role", ErrValidation, s.Type)
	}
	return nil
}

// Matches reports whether every condition holds for the subject (conditions are
// ANDed). A workflow with no conditions matches every subject.
func (d Doc) Matches(subject Subject) bool {
	for _, c := range d.Conditions {
		if !c.matches(subject) {
			return false
		}
	}
	return true
}

func (c Condition) matches(subject Subject) bool {
	actual := subject.attribute(c.Attribute)
	want := make(map[string]struct{}, len(c.Values))
	for _, v := range c.Values {
		want[strings.ToLower(v)] = struct{}{}
	}
	switch c.Operator {
	case OpEquals:
		_, ok := want[strings.ToLower(actual)]
		return ok && len(actual) > 0
	case OpNotEquals:
		_, ok := want[strings.ToLower(actual)]
		return !ok
	case OpIn:
		// Symmetric with OpEquals and fail-closed: a missing/empty attribute
		// must not satisfy a positive membership test, even if the author
		// listed an empty value.
		_, ok := want[strings.ToLower(actual)]
		return ok && len(actual) > 0
	case OpContains:
		for _, g := range subject.multi(c.Attribute) {
			if _, ok := want[strings.ToLower(g)]; ok {
				return true
			}
		}
		return false
	case OpNotContains:
		for _, g := range subject.multi(c.Attribute) {
			if _, ok := want[strings.ToLower(g)]; ok {
				return false
			}
		}
		return true
	default:
		// Unknown operators are rejected at Validate time; reaching here means a
		// stored doc predates a removed operator — fail closed (no match).
		return false
	}
}

// normalizeSet trims, drops empties, de-duplicates, and sorts a string set so a
// stored condition is deterministic.
func normalizeSet(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
