package billing

import (
	"sort"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/services/usage"
)

// LineItem is one metric's contribution to a statement: how much was included,
// how much was used, the resulting overage, and the integer amount (minor
// units) that overage costs. All counts and amounts are integers, so a line
// item never carries float drift.
type LineItem struct {
	Metric           string `json:"metric"`
	Included         int64  `json:"included"`
	Used             int64  `json:"used"`
	Overage          int64  `json:"overage"`
	OverageUnitMinor int64  `json:"overage_unit_minor"`
	OverageBlock     int64  `json:"overage_block"`
	AmountMinor      int64  `json:"amount_minor"`
}

// Statement is a tenant's structured, periodized bill: the plan it was on, the
// base charge, a line item per metric, and the integer totals. It carries NO
// wall-clock field, so it is a pure function of (workspace, period, plan, usage
// rows) — re-generating a closed period whose rollup rows are immutable yields a
// byte-identical Statement. That determinism is the idempotency contract the
// tests assert.
type Statement struct {
	WorkspaceID    uuid.UUID  `json:"workspace_id"`
	Period         string     `json:"period"`
	Plan           string     `json:"plan"`
	Currency       string     `json:"currency"`
	BasePriceMinor int64      `json:"base_price_minor"`
	LineItems      []LineItem `json:"line_items"`
	// OverageMinor is the summed overage across line items; TotalMinor is the
	// base price plus overage — the amount due for the period.
	OverageMinor int64 `json:"overage_minor"`
	TotalMinor   int64 `json:"total_minor"`
}

// ceilDiv returns ceil(n / d) for non-negative n and positive d, using only
// integer arithmetic so overage block counts never drift. A non-positive
// divisor is treated as 1 (per-unit billing) so a misconfigured OverageBlock
// can never divide by zero.
func ceilDiv(n, d int64) int64 {
	if d <= 0 {
		d = 1
	}
	if n <= 0 {
		return 0
	}
	return (n + d - 1) / d
}

// generateStatement derives the statement for one workspace/period from its
// resolved plan and its usage rollup rows. It is deterministic: line items are
// emitted in sorted metric order over the UNION of the plan's priced metrics
// and the metrics actually present in the rollup, so a metered-but-unpriced
// metric is still visible (zero included, zero amount) rather than silently
// dropped, and the ordering does not depend on map iteration.
func generateStatement(workspaceID uuid.UUID, period string, plan Plan, rows []usage.TenantUsage) Statement {
	used := make(map[string]int64, len(rows))
	for _, r := range rows {
		used[r.Metric] += r.Count
	}

	// Union of priced metrics and used metrics, sorted for deterministic output.
	metricSet := make(map[string]struct{}, len(plan.Metrics)+len(used))
	for m := range plan.Metrics {
		metricSet[m] = struct{}{}
	}
	for m := range used {
		metricSet[m] = struct{}{}
	}
	metrics := make([]string, 0, len(metricSet))
	for m := range metricSet {
		metrics = append(metrics, m)
	}
	sort.Strings(metrics)

	st := Statement{
		WorkspaceID:    workspaceID,
		Period:         period,
		Plan:           plan.Plan,
		Currency:       Currency,
		BasePriceMinor: plan.BasePriceMinor,
		LineItems:      make([]LineItem, 0, len(metrics)),
	}
	for _, metric := range metrics {
		q := plan.Metrics[metric] // zero value for an unpriced metric
		u := used[metric]
		overage := u - q.Included
		if overage < 0 {
			overage = 0
		}
		amount := ceilDiv(overage, q.OverageBlock) * q.OverageUnitMinor
		st.LineItems = append(st.LineItems, LineItem{
			Metric:           metric,
			Included:         q.Included,
			Used:             u,
			Overage:          overage,
			OverageUnitMinor: q.OverageUnitMinor,
			OverageBlock:     q.OverageBlock,
			AmountMinor:      amount,
		})
		st.OverageMinor += amount
	}
	st.TotalMinor = st.BasePriceMinor + st.OverageMinor
	return st
}
