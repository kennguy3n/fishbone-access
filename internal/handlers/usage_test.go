package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/services/usage"
)

// usageTestDeps extends the lifecycle test deps with a usage store (its own
// SQLite table), wiring both the read endpoint and the metering middleware so
// the wiring is exercised end-to-end through the real Auth + ResolveTenant +
// RequireTenant chain.
func usageTestDeps(t *testing.T) (Deps, *usage.Store) {
	t.Helper()
	deps := lifecycleTestDeps(t)
	store := usage.NewStore(deps.DB)
	if err := store.Migrate(); err != nil {
		t.Fatalf("usage migrate: %v", err)
	}
	aggregator := usage.New(store, usage.Config{})
	deps.UsageMeter = aggregator
	deps.UsageReader = store
	return deps, store
}

// workspaceIDForTenant looks up the seeded workspace UUID for a tenant so the
// test can write a rollup row the read endpoint should then return.
func workspaceIDForTenant(t *testing.T, deps Deps, tenant string) uuid.UUID {
	t.Helper()
	var ws struct{ ID uuid.UUID }
	if err := deps.DB.Table("workspaces").Select("id").Where("iam_core_tenant_id = ?", tenant).Scan(&ws).Error; err != nil {
		t.Fatalf("lookup workspace for %s: %v", tenant, err)
	}
	if ws.ID == uuid.Nil {
		t.Fatalf("no workspace seeded for tenant %s", tenant)
	}
	return ws.ID
}

// TestUsageReadReturnsCurrentPeriod proves GET /api/v1/usage returns the calling
// tenant's current-period rollup, shaped as a metric-keyed list.
func TestUsageReadReturnsCurrentPeriod(t *testing.T) {
	deps, store := usageTestDeps(t)
	r := NewRouter(deps)
	wsA := workspaceIDForTenant(t, deps, "tenant-a")

	if err := store.AddUsage(context.Background(), []usage.Delta{
		{WorkspaceID: wsA, Period: usage.PeriodOf(time.Now()), Metric: usage.MetricAPIRequests, Count: 42},
	}); err != nil {
		t.Fatalf("seed usage: %v", err)
	}

	w := do(t, r, http.MethodGet, "/api/v1/usage", "tok-a", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	var body struct {
		Period  string `json:"period"`
		Metrics []struct {
			Metric string `json:"metric"`
			Count  int64  `json:"count"`
		} `json:"metrics"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Period != usage.PeriodOf(time.Now()) {
		t.Fatalf("period = %q, want %q", body.Period, usage.PeriodOf(time.Now()))
	}
	if len(body.Metrics) != 1 || body.Metrics[0].Metric != usage.MetricAPIRequests || body.Metrics[0].Count != 42 {
		t.Fatalf("metrics = %+v, want one api_requests=42", body.Metrics)
	}
}

// TestUsageReadCrossTenantIsolation proves a tenant only ever sees its OWN
// usage: tenant-b's rollup is invisible to tenant-a's read.
func TestUsageReadCrossTenantIsolation(t *testing.T) {
	deps, store := usageTestDeps(t)
	r := NewRouter(deps)
	wsB := workspaceIDForTenant(t, deps, "tenant-b")

	if err := store.AddUsage(context.Background(), []usage.Delta{
		{WorkspaceID: wsB, Period: usage.PeriodOf(time.Now()), Metric: usage.MetricAPIRequests, Count: 99},
	}); err != nil {
		t.Fatalf("seed usage: %v", err)
	}

	// tenant-a has no usage of its own and must NOT see tenant-b's.
	w := do(t, r, http.MethodGet, "/api/v1/usage", "tok-a", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	var body struct {
		Metrics []json.RawMessage `json:"metrics"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(body.Metrics) != 0 {
		t.Fatalf("tenant-a saw %d metrics, want 0 (must not see tenant-b usage)", len(body.Metrics))
	}
}

// TestUsageReadEmptyIsSuccess proves an empty rollup is a 200 with an empty
// metric list (not a 404/500): the tenant simply has no usage yet.
func TestUsageReadEmptyIsSuccess(t *testing.T) {
	deps, _ := usageTestDeps(t)
	r := NewRouter(deps)

	w := do(t, r, http.MethodGet, "/api/v1/usage", "tok-a", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	var body struct {
		Period  string            `json:"period"`
		Metrics []json.RawMessage `json:"metrics"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Period == "" {
		t.Fatal("period empty; want the current period even with no usage")
	}
	if len(body.Metrics) != 0 {
		t.Fatalf("metrics = %v, want empty", body.Metrics)
	}
}

// TestUsageReadNotMountedWithoutReader proves the route is absent when no usage
// reader is wired (degraded boot), so the surface degrades cleanly rather than
// panicking on a nil reader.
func TestUsageReadNotMountedWithoutReader(t *testing.T) {
	deps := lifecycleTestDeps(t) // no UsageReader
	r := NewRouter(deps)

	w := do(t, r, http.MethodGet, "/api/v1/usage", "tok-a", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (route unmounted without a usage reader)", w.Code)
	}
}
