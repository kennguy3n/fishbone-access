package billing

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/services/tenancy"
	"github.com/kennguy3n/fishbone-access/internal/services/usage"
)

// row is a tiny helper for building a rollup row in a test.
func row(ws uuid.UUID, period, metric string, count int64) usage.TenantUsage {
	return usage.TenantUsage{WorkspaceID: ws, Period: period, Metric: metric, Count: count}
}

// TestCeilDiv covers the integer ceiling division that prices overage blocks,
// including the divide-by-zero guard (a misconfigured OverageBlock).
func TestCeilDiv(t *testing.T) {
	cases := []struct {
		n, d, want int64
	}{
		{0, 10_000, 0},
		{1, 10_000, 1},
		{10_000, 10_000, 1},
		{10_001, 10_000, 2},
		{25_000, 10_000, 3},
		{-5, 10_000, 0}, // negative overage never bills
		{5, 0, 5},       // non-positive divisor treated as per-unit (1), not a panic
		{5, -3, 5},      // negative divisor likewise
	}
	for _, c := range cases {
		if got := ceilDiv(c.n, c.d); got != c.want {
			t.Errorf("ceilDiv(%d,%d) = %d, want %d", c.n, c.d, got, c.want)
		}
	}
}

// TestGenerateStatementDeterministic proves the statement is a pure function of
// its inputs: the same (workspace, period, plan, rows) — even with the rows in a
// different order — yields a byte-identical statement. This is the idempotency
// contract for re-generating a closed period.
func TestGenerateStatementDeterministic(t *testing.T) {
	ws := uuid.New()
	plan := resolvePlan(TenantPlan{Plan: tenancy.TierBase})

	rowsA := []usage.TenantUsage{
		row(ws, "2026-06", usage.MetricAPIRequests, 600_000),
		row(ws, "2026-06", "active_pam_sessions", 12),
	}
	// Same logical usage, different row order AND split across two rows for the
	// same metric (the rollup may hold per-replica fragments before coalescing).
	rowsB := []usage.TenantUsage{
		row(ws, "2026-06", "active_pam_sessions", 12),
		row(ws, "2026-06", usage.MetricAPIRequests, 100_000),
		row(ws, "2026-06", usage.MetricAPIRequests, 500_000),
	}

	a := generateStatement(ws, "2026-06", plan, rowsA)
	b := generateStatement(ws, "2026-06", plan, rowsB)

	if !reflect.DeepEqual(a, b) {
		t.Fatalf("statements differ:\n a=%+v\n b=%+v", a, b)
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if !bytes.Equal(ja, jb) {
		t.Fatalf("statement JSON not byte-identical:\n a=%s\n b=%s", ja, jb)
	}

	// Line items must be in sorted metric order regardless of input order.
	if len(a.LineItems) != 2 || a.LineItems[0].Metric != "active_pam_sessions" || a.LineItems[1].Metric != usage.MetricAPIRequests {
		t.Fatalf("line items not in sorted metric order: %+v", a.LineItems)
	}
}

// TestGenerateStatementOverageMath checks the integer overage pricing on a paid
// plan: usage over the included quota bills in coarse blocks at the unit price,
// and the totals are base + overage.
func TestGenerateStatementOverageMath(t *testing.T) {
	ws := uuid.New()
	plan := resolvePlan(TenantPlan{Plan: tenancy.TierBase}) // incl 1_000_000, block 10_000, unit 50, base 4_900

	st := generateStatement(ws, "2026-06", plan, []usage.TenantUsage{
		row(ws, "2026-06", usage.MetricAPIRequests, 1_025_000), // 25_000 over -> 3 blocks
	})

	if len(st.LineItems) != 1 {
		t.Fatalf("want 1 line item, got %+v", st.LineItems)
	}
	li := st.LineItems[0]
	if li.Overage != 25_000 {
		t.Errorf("overage = %d, want 25_000", li.Overage)
	}
	// 25_000 over the included quota bills as three 10_000 blocks at 50 minor each.
	if li.AmountMinor != 150 {
		t.Errorf("amount = %d, want 150", li.AmountMinor)
	}
	if st.OverageMinor != 150 {
		t.Errorf("overage total = %d, want 150", st.OverageMinor)
	}
	if st.TotalMinor != 5_050 { // base 4900 + 150
		t.Errorf("total = %d, want 5050", st.TotalMinor)
	}
	if st.Currency != Currency {
		t.Errorf("currency = %q, want %q", st.Currency, Currency)
	}
}

// TestGenerateStatementWithinQuotaNoOverage proves usage at or below the
// included quota bills only the base price.
func TestGenerateStatementWithinQuotaNoOverage(t *testing.T) {
	ws := uuid.New()
	plan := resolvePlan(TenantPlan{Plan: tenancy.TierPro}) // incl 10_000_000, base 19_900

	st := generateStatement(ws, "2026-06", plan, []usage.TenantUsage{
		row(ws, "2026-06", usage.MetricAPIRequests, 10_000_000), // exactly included
	})
	if st.LineItems[0].Overage != 0 || st.OverageMinor != 0 {
		t.Fatalf("expected no overage at exactly the included quota: %+v", st)
	}
	if st.TotalMinor != 19_900 {
		t.Errorf("total = %d, want 19900 (base only)", st.TotalMinor)
	}
}

// TestGenerateStatementUnpricedMetricVisible proves a metered-but-unpriced
// metric still appears as a zero-amount line item rather than being silently
// dropped — the statement is an honest record of everything metered.
func TestGenerateStatementUnpricedMetricVisible(t *testing.T) {
	ws := uuid.New()
	plan := resolvePlan(TenantPlan{Plan: tenancy.TierTrial})

	st := generateStatement(ws, "2026-06", plan, []usage.TenantUsage{
		row(ws, "2026-06", "active_pam_sessions", 7),
	})

	var found *LineItem
	for i := range st.LineItems {
		if st.LineItems[i].Metric == "active_pam_sessions" {
			found = &st.LineItems[i]
		}
	}
	if found == nil {
		t.Fatalf("unpriced metric missing from statement: %+v", st.LineItems)
	}
	if found.Included != 0 || found.AmountMinor != 0 || found.Used != 7 {
		t.Errorf("unpriced line item = %+v, want included=0 amount=0 used=7", *found)
	}
}

// TestGenerateStatementEmptyUsage proves a period with no usage is a valid,
// fully determined statement (base price, zero overage), not an error or an
// empty struct.
func TestGenerateStatementEmptyUsage(t *testing.T) {
	ws := uuid.New()
	plan := resolvePlan(TenantPlan{Plan: tenancy.TierBase})

	st := generateStatement(ws, "2026-06", plan, nil)
	if st.TotalMinor != 4_900 || st.OverageMinor != 0 {
		t.Errorf("empty-usage statement = base only? got total=%d overage=%d", st.TotalMinor, st.OverageMinor)
	}
	// The priced metric is still listed with zero usage.
	if len(st.LineItems) != 1 || st.LineItems[0].Used != 0 {
		t.Errorf("want one zero-usage line item, got %+v", st.LineItems)
	}
}
