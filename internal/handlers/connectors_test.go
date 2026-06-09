package handlers

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// TestConnectorCatalogueListReturnsEveryProvider asserts the catalogue endpoint
// surfaces one entry per curated connector and that the response is tenant
// scoped (served under RequireTenant).
func TestConnectorCatalogueListReturnsEveryProvider(t *testing.T) {
	r := NewRouter(lifecycleTestDeps(t))

	w := do(t, r, http.MethodGet, "/api/v1/connectors", "tok-a", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list status = %d, body=%s", w.Code, w.Body.String())
	}
	var body struct {
		Connectors []access.ConnectorCatalogueEntry `json:"connectors"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(body.Connectors) != len(access.ListCapabilityDescriptors()) {
		t.Fatalf("catalogue returned %d entries, want %d", len(body.Connectors), len(access.ListCapabilityDescriptors()))
	}
	// Nothing is connected for a fresh workspace.
	for _, e := range body.Connectors {
		if e.Connected {
			t.Fatalf("provider %s reported connected in a fresh workspace", e.Provider)
		}
	}
}

// TestConnectorCatalogueCapabilityFilter asserts the ?capability= filter narrows
// the result to providers advertising that capability, and that the subset is
// non-empty and strictly smaller than the full catalogue.
func TestConnectorCatalogueCapabilityFilter(t *testing.T) {
	r := NewRouter(lifecycleTestDeps(t))

	w := do(t, r, http.MethodGet, "/api/v1/connectors?capability="+access.CapabilitySSOFederation, "tok-a", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("filtered list status = %d, body=%s", w.Code, w.Body.String())
	}
	var body struct {
		Connectors []access.ConnectorCatalogueEntry `json:"connectors"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(body.Connectors) == 0 {
		t.Fatal("sso_federation filter returned no connectors")
	}
	full := len(access.ListCapabilityDescriptors())
	if len(body.Connectors) >= full {
		t.Fatalf("filter did not narrow the catalogue: got %d of %d", len(body.Connectors), full)
	}
	for _, e := range body.Connectors {
		if !e.UserFacing.SSOFederation {
			t.Fatalf("provider %s in sso_federation filter does not advertise it", e.Provider)
		}
	}
}

// TestConnectorCatalogueInvalidConnectedFilter asserts an unparseable connected=
// filter is rejected (400), not silently ignored.
func TestConnectorCatalogueInvalidConnectedFilter(t *testing.T) {
	r := NewRouter(lifecycleTestDeps(t))
	w := do(t, r, http.MethodGet, "/api/v1/connectors?connected=maybe", "tok-a", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid connected filter status = %d, want 400", w.Code)
	}
}

// TestConnectorCatalogueConnectedFilterTriState asserts the connected= filter
// is tri-state: omitted returns the full catalogue, connected=false returns
// only disconnected providers, and connected=true returns only connected ones.
// With no DB every provider is disconnected, so connected=false must return the
// full catalogue (not a no-op) and connected=true must return nothing — this is
// the regression guard for connected=false having been silently ignored.
func TestConnectorCatalogueConnectedFilterTriState(t *testing.T) {
	r := NewRouter(lifecycleTestDeps(t))
	full := len(access.ListCapabilityDescriptors())

	list := func(query string) []access.ConnectorCatalogueEntry {
		t.Helper()
		w := do(t, r, http.MethodGet, "/api/v1/connectors"+query, "tok-a", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("list%s status = %d, body=%s", query, w.Code, w.Body.String())
		}
		var body struct {
			Connectors []access.ConnectorCatalogueEntry `json:"connectors"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return body.Connectors
	}

	if got := len(list("?connected=false")); got != full {
		t.Fatalf("connected=false returned %d entries, want all %d (none are connected)", got, full)
	}
	if got := len(list("?connected=true")); got != 0 {
		t.Fatalf("connected=true returned %d entries, want 0 (none are connected)", got)
	}
	if got := len(list("")); got != full {
		t.Fatalf("omitted filter returned %d entries, want all %d", got, full)
	}
}

// TestConnectorCatalogueDetail asserts the provider-keyed detail endpoint
// returns the descriptor for a known provider and 404s an unknown one.
func TestConnectorCatalogueDetail(t *testing.T) {
	r := NewRouter(lifecycleTestDeps(t))

	// Pick any registered provider from the live catalogue.
	descriptors := access.ListCapabilityDescriptors()
	if len(descriptors) == 0 {
		t.Skip("no connectors registered")
	}
	provider := descriptors[0].Provider

	w := do(t, r, http.MethodGet, "/api/v1/connectors/catalogue/"+provider, "tok-a", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("detail status = %d, body=%s", w.Code, w.Body.String())
	}
	var entry access.ConnectorCatalogueEntry
	if err := json.Unmarshal(w.Body.Bytes(), &entry); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if entry.Provider != provider {
		t.Fatalf("detail provider = %q, want %q", entry.Provider, provider)
	}

	w404 := do(t, r, http.MethodGet, "/api/v1/connectors/catalogue/this-provider-does-not-exist", "tok-a", nil)
	if w404.Code != http.StatusNotFound {
		t.Fatalf("unknown provider status = %d, want 404", w404.Code)
	}
}

// TestConnectorCatalogueFacets asserts the facets endpoint returns the filter
// vocabularies the gallery renders its controls from.
func TestConnectorCatalogueFacets(t *testing.T) {
	r := NewRouter(lifecycleTestDeps(t))
	w := do(t, r, http.MethodGet, "/api/v1/connectors/catalogue/facets", "tok-a", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("facets status = %d, body=%s", w.Code, w.Body.String())
	}
	var facets access.CatalogueFacets
	if err := json.Unmarshal(w.Body.Bytes(), &facets); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(facets.Tiers) == 0 || len(facets.UserFacingCapabilities) == 0 {
		t.Fatalf("facets missing vocabularies: %+v", facets)
	}
}

// TestConnectorSetupWizardFailOpen is the AI-assistant handler test: with no AI
// client configured (deps.AI is nil — the model is "unavailable"), the wizard
// must still return 200 with a degraded manual plan rather than a 5xx, and the
// plan must contain actionable steps so a human can proceed manually.
func TestConnectorSetupWizardFailOpen(t *testing.T) {
	deps := lifecycleTestDeps(t)
	// deps.AI is nil here: the connector_setup_assistant skill is unreachable,
	// exercising the fail-OPEN path end to end through the HTTP handler.
	r := NewRouter(deps)

	descriptors := access.ListCapabilityDescriptors()
	if len(descriptors) == 0 {
		t.Skip("no connectors registered")
	}
	provider := descriptors[0].Provider

	w := do(t, r, http.MethodPost, "/api/v1/connectors/catalogue/"+provider+"/setup-wizard", "tok-a", map[string]any{
		"admin_intent": "Connect our directory and sync identities nightly.",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("setup-wizard status = %d, want 200 (fail-open); body=%s", w.Code, w.Body.String())
	}
	var res struct {
		SuggestionID string `json:"suggestion_id"`
		Plan         struct {
			Degraded bool `json:"degraded"`
			Steps    []struct {
				Title string `json:"title"`
			} `json:"steps"`
		} `json:"plan"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !res.Plan.Degraded {
		t.Fatal("expected a degraded plan when the model is unavailable")
	}
	if len(res.Plan.Steps) == 0 {
		t.Fatal("degraded plan has no steps; a human cannot proceed manually")
	}
	if res.SuggestionID == "" {
		t.Fatal("suggestion was not persisted (empty suggestion_id)")
	}
}

// TestConnectorSetupWizardUnknownProvider asserts the wizard validates the
// provider against the live registry and 400s an unknown one.
func TestConnectorSetupWizardUnknownProvider(t *testing.T) {
	r := NewRouter(lifecycleTestDeps(t))
	w := do(t, r, http.MethodPost, "/api/v1/connectors/catalogue/not-a-real-provider/setup-wizard", "tok-a", map[string]any{
		"admin_intent": "x",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown provider wizard status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

// TestConnectorCatalogueRequiresAuth asserts the catalogue is on the
// tenant-scoped surface: without a token the request is rejected, never served
// unscoped.
func TestConnectorCatalogueRequiresAuth(t *testing.T) {
	r := NewRouter(lifecycleTestDeps(t))
	w := do(t, r, http.MethodGet, "/api/v1/connectors", "", nil)
	if w.Code == http.StatusOK {
		t.Fatalf("catalogue served without auth (status %d)", w.Code)
	}
}
