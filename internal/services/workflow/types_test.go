package workflow

import (
	"errors"
	"strings"
	"testing"
)

const testConnID = "11111111-1111-1111-1111-111111111111"

func TestParseDoc_Valid(t *testing.T) {
	raw := `{
		"kind": "joiner",
		"trigger": "identity_event",
		"conditions": [{"attribute": "department", "operator": "eq", "values": ["Sales"]}],
		"steps": [
			{"type": "grant_role", "connector_id": "` + testConnID + `", "resource_ref": "crm", "role": "viewer"},
			{"type": "notify", "channel": "email", "message": "welcome"}
		]
	}`
	doc, err := ParseDoc([]byte(raw))
	if err != nil {
		t.Fatalf("ParseDoc valid: %v", err)
	}
	if doc.Kind != KindJoiner || doc.Trigger != TriggerIdentityEvent {
		t.Fatalf("unexpected decode: %+v", doc)
	}
	if len(doc.Steps) != 2 {
		t.Fatalf("steps = %d, want 2", len(doc.Steps))
	}
}

func TestParseDoc_RejectsUnknownField(t *testing.T) {
	raw := `{"kind":"joiner","trigger":"manual","stepz":[],"steps":[{"type":"notify","channel":"email"}]}`
	_, err := ParseDoc([]byte(raw))
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation for unknown field, got %v", err)
	}
}

func TestParseDoc_Empty(t *testing.T) {
	if _, err := ParseDoc(nil); !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation for empty doc, got %v", err)
	}
}

func TestValidate_TableDriven(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantErr bool
		errHas  string
	}{
		{
			name: "valid leaver with kill switch",
			raw:  `{"kind":"leaver","trigger":"identity_event","steps":[{"type":"run_kill_switch"}]}`,
		},
		{
			name:    "kill switch on joiner rejected",
			raw:     `{"kind":"joiner","trigger":"manual","steps":[{"type":"run_kill_switch"}]}`,
			wantErr: true,
			errHas:  "run_kill_switch is only allowed on a leaver",
		},
		{
			name:    "unknown kind",
			raw:     `{"kind":"intern","trigger":"manual","steps":[{"type":"notify","channel":"email"}]}`,
			wantErr: true,
			errHas:  "workflow kind",
		},
		{
			name:    "unknown trigger",
			raw:     `{"kind":"joiner","trigger":"webhook","steps":[{"type":"notify","channel":"email"}]}`,
			wantErr: true,
			errHas:  "workflow trigger",
		},
		{
			name:    "unknown step type",
			raw:     `{"kind":"joiner","trigger":"manual","steps":[{"type":"teleport"}]}`,
			wantErr: true,
			errHas:  "unknown step type",
		},
		{
			name:    "empty pipeline",
			raw:     `{"kind":"joiner","trigger":"manual","steps":[]}`,
			wantErr: true,
			errHas:  "at least one step",
		},
		{
			name:    "grant_role missing connector",
			raw:     `{"kind":"joiner","trigger":"manual","steps":[{"type":"grant_role","resource_ref":"crm","role":"viewer"}]}`,
			wantErr: true,
			errHas:  "requires a connector_id",
		},
		{
			name:    "grant_role bad connector uuid",
			raw:     `{"kind":"joiner","trigger":"manual","steps":[{"type":"grant_role","connector_id":"not-a-uuid","resource_ref":"crm","role":"viewer"}]}`,
			wantErr: true,
			errHas:  "not a valid id",
		},
		{
			name:    "request_approval needs approver_role",
			raw:     `{"kind":"joiner","trigger":"manual","steps":[{"type":"request_approval","connector_id":"` + testConnID + `","resource_ref":"crm","role":"admin"}]}`,
			wantErr: true,
			errHas:  "approver_role",
		},
		{
			name:    "notify needs channel",
			raw:     `{"kind":"joiner","trigger":"manual","steps":[{"type":"notify","message":"hi"}]}`,
			wantErr: true,
			errHas:  "notify step requires a channel",
		},
		{
			name:    "start_access_review needs review_name",
			raw:     `{"kind":"mover","trigger":"manual","steps":[{"type":"start_access_review"}]}`,
			wantErr: true,
			errHas:  "review_name",
		},
		{
			name:    "condition missing values",
			raw:     `{"kind":"joiner","trigger":"manual","conditions":[{"attribute":"department","operator":"eq","values":[]}],"steps":[{"type":"notify","channel":"email"}]}`,
			wantErr: true,
			errHas:  "needs at least one value",
		},
		{
			name:    "condition unknown operator",
			raw:     `{"kind":"joiner","trigger":"manual","conditions":[{"attribute":"department","operator":"regex","values":["x"]}],"steps":[{"type":"notify","channel":"email"}]}`,
			wantErr: true,
			errHas:  "unknown operator",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseDoc([]byte(tc.raw))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if !errors.Is(err, ErrValidation) {
					t.Fatalf("expected ErrValidation, got %v", err)
				}
				if tc.errHas != "" && !strings.Contains(err.Error(), tc.errHas) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.errHas)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestMatches(t *testing.T) {
	sales := Subject{ExternalID: "u1", Department: "Sales", Groups: []string{"eng", "oncall"}}
	cases := []struct {
		name string
		cond Condition
		subj Subject
		want bool
	}{
		{"eq department match", Condition{"department", OpEquals, []string{"Sales"}}, sales, true},
		{"eq department case-insensitive", Condition{"department", OpEquals, []string{"sales"}}, sales, true},
		{"eq department miss", Condition{"department", OpEquals, []string{"Finance"}}, sales, false},
		{"neq department", Condition{"department", OpNotEquals, []string{"Finance"}}, sales, true},
		{"in department", Condition{"department", OpIn, []string{"Finance", "Sales"}}, sales, true},
		{"contains group", Condition{"groups", OpContains, []string{"oncall"}}, sales, true},
		{"contains group miss", Condition{"groups", OpContains, []string{"sre"}}, sales, false},
		{"not_contains group", Condition{"groups", OpNotContains, []string{"sre"}}, sales, true},
		{"not_contains group hit", Condition{"groups", OpNotContains, []string{"eng"}}, sales, false},
		{"eq empty attr fails", Condition{"department", OpEquals, []string{""}}, Subject{ExternalID: "u2"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := Doc{Conditions: []Condition{tc.cond}}
			if got := doc.Matches(tc.subj); got != tc.want {
				t.Fatalf("Matches = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMatches_NoConditionsMatchesAll(t *testing.T) {
	doc := Doc{}
	if !doc.Matches(Subject{ExternalID: "anyone"}) {
		t.Fatal("a workflow with no conditions must match every subject")
	}
}
