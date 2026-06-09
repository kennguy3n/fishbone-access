package database

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

// persistedFieldNames returns the set of GORM-persisted field names of a struct
// type, flattening anonymous embedded structs (e.g. models.Base) and skipping
// fields explicitly excluded from persistence with a `gorm:"-"` tag. It is the
// reflective notion of "which columns this struct maps to", used by the drift
// guard below.
func persistedFieldNames(t reflect.Type) map[string]struct{} {
	out := map[string]struct{}{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Anonymous && f.Type.Kind() == reflect.Struct {
			for name := range persistedFieldNames(f.Type) {
				out[name] = struct{}{}
			}
			continue
		}
		if tag, ok := f.Tag.Lookup("gorm"); ok && strings.HasPrefix(tag, "-") {
			continue
		}
		out[f.Name] = struct{}{}
	}
	return out
}

func sortedKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// TestWorkspaceAdapterMirrorsModel is the drift guard for the pgx workspace
// adapter. The adapter deliberately does NOT import internal/models for its
// mirror struct (workspacesModel) or its read view (WorkspaceConfig) — doing so
// would couple the package to the full models graph — so the field sets are
// maintained by hand. That hand-maintenance is the risk: if models.Workspace
// gains a persisted column, workspacesModel, WorkspaceConfig and the SELECT in
// PgxWorkspaceConfigRepo.Workspace would silently omit it and the two backends
// would diverge.
//
// This test fails the moment models.Workspace's persisted field set changes
// without the adapter being updated in lockstep, forcing the author to extend
// workspacesModel, WorkspaceConfig and the pgx query together. It is a plain
// unit test (no integration tag) so it runs on every `go test ./...`.
func TestWorkspaceAdapterMirrorsModel(t *testing.T) {
	model := persistedFieldNames(reflect.TypeOf(models.Workspace{}))
	mirror := persistedFieldNames(reflect.TypeOf(workspacesModel{}))

	if !reflect.DeepEqual(model, mirror) {
		t.Fatalf("workspacesModel has drifted from models.Workspace.\n"+
			"models.Workspace persisted fields: %v\n"+
			"workspacesModel fields:            %v\n"+
			"Update workspacesModel, WorkspaceConfig and the SELECT in Workspace() together.",
			sortedKeys(model), sortedKeys(mirror))
	}

	// WorkspaceConfig is the read view: every model field except the
	// soft-delete marker (reads return live rows only, so DeletedAt is never
	// surfaced). Tie it to the model too, so a new column must also be exposed
	// on the read view (and therefore selected by the pgx/GORM Workspace query).
	want := map[string]struct{}{}
	for name := range model {
		if name == "DeletedAt" {
			continue
		}
		want[name] = struct{}{}
	}
	view := persistedFieldNames(reflect.TypeOf(WorkspaceConfig{}))
	if !reflect.DeepEqual(want, view) {
		t.Fatalf("WorkspaceConfig read view has drifted from models.Workspace.\n"+
			"expected (model minus DeletedAt): %v\n"+
			"WorkspaceConfig fields:           %v\n"+
			"Add the new column to WorkspaceConfig and the SELECT in Workspace().",
			sortedKeys(want), sortedKeys(view))
	}
}
