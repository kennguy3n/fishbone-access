package handlers

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/kennguy3n/fishbone-access/internal/models"
)

func TestPacksListAndFilter(t *testing.T) {
	r := NewRouter(lifecycleTestDeps(t))

	// Auth required.
	if w := do(t, r, http.MethodGet, "/api/v1/packs", "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauth list = %d, want 401", w.Code)
	}

	w := do(t, r, http.MethodGet, "/api/v1/packs", "tok-a", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list = %d, body=%s", w.Code, w.Body.String())
	}
	var listed struct {
		Packs []struct {
			ID   string `json:"id"`
			Tier int    `json:"tier"`
		} `json:"packs"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(listed.Packs) < 15 {
		t.Fatalf("expected populated catalog, got %d", len(listed.Packs))
	}

	// Tier filter.
	w = do(t, r, http.MethodGet, "/api/v1/packs?tier=1", "tok-a", nil)
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode tier: %v", err)
	}
	for _, p := range listed.Packs {
		if p.Tier != 1 {
			t.Fatalf("tier filter leaked tier %d", p.Tier)
		}
	}

	// Bad tier → 400.
	if w := do(t, r, http.MethodGet, "/api/v1/packs?tier=abc", "tok-a", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("bad tier = %d, want 400", w.Code)
	}
}

func TestPackGet(t *testing.T) {
	r := NewRouter(lifecycleTestDeps(t))

	w := do(t, r, http.MethodGet, "/api/v1/packs/pci-dss-v4", "tok-a", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get = %d, body=%s", w.Code, w.Body.String())
	}
	if w := do(t, r, http.MethodGet, "/api/v1/packs/nope", "tok-a", nil); w.Code != http.StatusNotFound {
		t.Fatalf("unknown pack = %d, want 404", w.Code)
	}
}

func TestPackApplyMaterializesDraftsForTenant(t *testing.T) {
	r := NewRouter(lifecycleTestDeps(t))

	w := do(t, r, http.MethodPost, "/api/v1/packs/pci-dss-v4/apply", "tok-a", map[string]any{
		"template_keys": []string{"cde-admins-only"},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("apply = %d, body=%s", w.Code, w.Body.String())
	}
	var applied struct {
		Applied []struct {
			TemplateKey string         `json:"template_key"`
			Policy      *models.Policy `json:"policy"`
		} `json:"applied"`
		Count int `json:"count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &applied); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if applied.Count != 1 || applied.Applied[0].Policy == nil {
		t.Fatalf("expected one applied draft, got %+v", applied)
	}
	if applied.Applied[0].Policy.State != "draft" {
		t.Fatalf("expected draft, got %q", applied.Applied[0].Policy.State)
	}

	// The draft is visible to its own tenant's policy list...
	w = do(t, r, http.MethodGet, "/api/v1/policies", "tok-a", nil)
	var pols struct {
		Policies []models.Policy `json:"policies"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &pols)
	if len(pols.Policies) != 1 {
		t.Fatalf("tenant-a should see 1 policy, got %d", len(pols.Policies))
	}
	// ...and NOT to another tenant (workspace isolation).
	w = do(t, r, http.MethodGet, "/api/v1/policies", "tok-b", nil)
	_ = json.Unmarshal(w.Body.Bytes(), &pols)
	if len(pols.Policies) != 0 {
		t.Fatalf("tenant-b should see 0 policies, got %d", len(pols.Policies))
	}

	// Unknown template in a real pack → 400.
	w = do(t, r, http.MethodPost, "/api/v1/packs/pci-dss-v4/apply", "tok-a", map[string]any{
		"template_keys": []string{"ghost"},
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown template apply = %d, want 400, body=%s", w.Code, w.Body.String())
	}
}
