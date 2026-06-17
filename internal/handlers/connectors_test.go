package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/iamcore"
	"github.com/kennguy3n/fishbone-access/internal/services/access"
)

// fakeSSOConnections is an in-memory access.ConnectionConfigurator for the
// connector SSO federation handler tests. It records the created connection and
// the last deleted id so the endpoint behaviour can be asserted without a live
// iam-core.
type fakeSSOConnections struct {
	created   *iamcore.Connection
	deletedID string
}

func (f *fakeSSOConnections) CreateConnection(_ context.Context, conn iamcore.Connection) (*iamcore.Connection, error) {
	conn.ID = "conn-xyz"
	f.created = &conn
	return &conn, nil
}
func (f *fakeSSOConnections) DeleteConnection(_ context.Context, id string) error {
	f.deletedID = id
	return nil
}
func (f *fakeSSOConnections) TestConnection(context.Context, string) error         { return nil }
func (f *fakeSSOConnections) ToggleConnection(context.Context, string, bool) error { return nil }

// createOktaConnector creates an okta connector via the API and returns its id.
func createOktaConnector(t *testing.T, r http.Handler) string {
	t.Helper()
	wc := do(t, r, http.MethodPost, "/api/v1/connectors", "tok-a", map[string]any{
		"provider": "okta",
		"secrets":  map[string]any{"sso_client_id": "cid", "sso_client_secret": "sec"},
	})
	if wc.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body=%s", wc.Code, wc.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(wc.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal create: %v", err)
	}
	return created.ID
}

// TestConnectorSSOFederationEndpoints exercises the full POST/DELETE
// /connectors/{id}/sso surface against a wired (fake) iam-core configurator: a
// federating connector returns 200 with a SAFE projection (no client_secret),
// and DELETE tears the connection down (204).
func TestConnectorSSOFederationEndpoints(t *testing.T) {
	access.SwapConnector(t, "okta", &access.MockAccessConnector{
		FuncGetSSOMetadata: func(context.Context, map[string]interface{}, map[string]interface{}) (*access.SSOMetadata, error) {
			return &access.SSOMetadata{Protocol: "oidc", MetadataURL: "https://idp.example.com/.well-known/openid-configuration"}, nil
		},
	})
	deps := lifecycleTestDeps(t)
	fake := &fakeSSOConnections{}
	deps.SSOConnections = fake
	r := NewRouter(deps)
	id := createOktaConnector(t, r)

	// POST → 200, federated.
	w := do(t, r, http.MethodPost, "/api/v1/connectors/"+id+"/sso", "tok-a", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("configure sso status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `"strategy":"oidc"`) {
		t.Errorf("response missing strategy: %s", body)
	}
	// The registered client_secret must never be echoed back.
	if strings.Contains(body, "sec") || strings.Contains(body, "client_secret") {
		t.Errorf("federation secret leaked in response body: %s", body)
	}
	if fake.created == nil {
		t.Fatal("no iam-core connection was created")
	}

	// DELETE → 204, connection removed.
	wd := do(t, r, http.MethodDelete, "/api/v1/connectors/"+id+"/sso", "tok-a", nil)
	if wd.Code != http.StatusNoContent {
		t.Fatalf("remove sso status = %d, want 204; body=%s", wd.Code, wd.Body.String())
	}
	if fake.deletedID != "conn-xyz" {
		t.Errorf("deleted connection = %q, want conn-xyz", fake.deletedID)
	}
}

// TestConnectorSSOFederationDisabled pins that a deployment without iam-core
// management credentials (no SSOConnections wired) fails-soft with 503, never a
// panic.
func TestConnectorSSOFederationDisabled(t *testing.T) {
	access.SwapConnector(t, "okta", &access.MockAccessConnector{
		FuncGetSSOMetadata: func(context.Context, map[string]interface{}, map[string]interface{}) (*access.SSOMetadata, error) {
			return &access.SSOMetadata{Protocol: "oidc", MetadataURL: "https://idp.example.com/.well-known/openid-configuration"}, nil
		},
	})
	r := NewRouter(lifecycleTestDeps(t)) // no SSOConnections
	id := createOktaConnector(t, r)

	w := do(t, r, http.MethodPost, "/api/v1/connectors/"+id+"/sso", "tok-a", nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("configure sso (disabled) status = %d, want 503; body=%s", w.Code, w.Body.String())
	}
}

// TestConnectorSSOFederationUnsupported pins that a connector which does not
// advertise SSO metadata returns 422 (not a 500/panic) when federation is wired.
func TestConnectorSSOFederationUnsupported(t *testing.T) {
	access.SwapConnector(t, "okta", &access.MockAccessConnector{
		FuncGetSSOMetadata: func(context.Context, map[string]interface{}, map[string]interface{}) (*access.SSOMetadata, error) {
			return nil, nil // does not federate
		},
	})
	deps := lifecycleTestDeps(t)
	deps.SSOConnections = &fakeSSOConnections{}
	r := NewRouter(deps)
	id := createOktaConnector(t, r)

	w := do(t, r, http.MethodPost, "/api/v1/connectors/"+id+"/sso", "tok-a", nil)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("configure sso (unsupported) status = %d, want 422; body=%s", w.Code, w.Body.String())
	}
}

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

// TestConnectorSetupSchemaCurated asserts the setup-schema endpoint returns a
// well-formed guided schema for a curated provider, with the display name
// resolved from the registry and at least one auth method carrying fields.
func TestConnectorSetupSchemaCurated(t *testing.T) {
	r := NewRouter(lifecycleTestDeps(t))

	w := do(t, r, http.MethodGet, "/api/v1/connectors/catalogue/okta/setup-schema", "tok-a", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("setup-schema status = %d, body=%s", w.Code, w.Body.String())
	}
	var body struct {
		Schema *access.ConnectorSetupSchema `json:"schema"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Schema == nil {
		t.Fatal("expected a curated schema for okta, got null")
	}
	if body.Schema.Provider != "okta" {
		t.Fatalf("schema provider = %q, want okta", body.Schema.Provider)
	}
	if body.Schema.DisplayName == "" {
		t.Fatal("schema display name not resolved from the registry")
	}
	if len(body.Schema.AuthMethods) == 0 || len(body.Schema.AuthMethods[0].Fields) == 0 {
		t.Fatalf("schema has no auth methods/fields: %+v", body.Schema)
	}
}

// TestConnectorSetupSchemaNoCuratedSchema asserts a registered provider with no
// curated schema returns 200 with {"schema": null} (not a 404), so the client
// cleanly falls back to the manual editor.
func TestConnectorSetupSchemaNoCuratedSchema(t *testing.T) {
	// Find a registered provider that has no curated setup schema.
	var provider string
	for _, d := range access.ListCapabilityDescriptors() {
		if !access.HasSetupSchema(d.Provider) {
			provider = d.Provider
			break
		}
	}
	if provider == "" {
		t.Skip("every registered provider has a curated schema")
	}
	r := NewRouter(lifecycleTestDeps(t))
	w := do(t, r, http.MethodGet, "/api/v1/connectors/catalogue/"+provider+"/setup-schema", "tok-a", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("no-schema status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var body struct {
		Schema *access.ConnectorSetupSchema `json:"schema"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Schema != nil {
		t.Fatalf("expected null schema for %q, got %+v", provider, body.Schema)
	}
}

// TestConnectorSetupSchemaUnknownProvider asserts an unknown provider is a 404.
func TestConnectorSetupSchemaUnknownProvider(t *testing.T) {
	r := NewRouter(lifecycleTestDeps(t))
	w := do(t, r, http.MethodGet, "/api/v1/connectors/catalogue/not-a-real-provider/setup-schema", "tok-a", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown provider status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
}

// TestConnectorTestConnectivityMissingSerializesAsEmptyArray pins the OpenAPI
// contract for the `missing` field: it is typed as a non-nullable array, so even
// when no capabilities are probed (the service returns a nil Go slice) the JSON
// body must carry "missing":[] rather than "missing":null, or strict client-side
// schema validators would reject an otherwise-successful 200.
func TestConnectorTestConnectivityMissingSerializesAsEmptyArray(t *testing.T) {
	// A bare mock connects cleanly (default Connect/Validate return nil), so the
	// test endpoint reaches the 200 path with no capabilities requested.
	access.SwapConnector(t, "test-provider", &access.MockAccessConnector{})
	r := NewRouter(lifecycleTestDeps(t))

	wc := do(t, r, http.MethodPost, "/api/v1/connectors", "tok-a", map[string]any{
		"provider": "test-provider",
		"secrets":  map[string]any{"token": "s3cr3t"},
	})
	if wc.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body=%s", wc.Code, wc.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(wc.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal create: %v", err)
	}

	wt := do(t, r, http.MethodPost, "/api/v1/connectors/"+created.ID+"/test", "tok-a", nil)
	if wt.Code != http.StatusOK {
		t.Fatalf("test status = %d, want 200; body=%s", wt.Code, wt.Body.String())
	}
	body := wt.Body.String()
	if strings.Contains(body, `"missing":null`) {
		t.Fatalf("missing serialized as JSON null, want []: %s", body)
	}
	if !strings.Contains(body, `"missing":[]`) {
		t.Fatalf("expected \"missing\":[] in body, got: %s", body)
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
