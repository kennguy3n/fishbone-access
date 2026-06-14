package billing

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/fishbone-access/internal/services/usage"
)

// defaultCacheTTL bounds how long a per-workspace quota decision is reused
// before a refresh when the operator does not configure one. It trades a small
// enforcement lag for zero per-request DB reads; combined with the meter's flush
// interval it is the TTL-bounded window over which replicas converge.
const defaultCacheTTL = 30 * time.Second

// defaultIdleTTL is how long an unused per-workspace cache entry is retained
// before the janitor evicts it, bounding memory to the ACTIVE-tenant count
// rather than the all-time count (trials churn). A returning tenant simply
// re-loads its decision, so eviction is safe.
const defaultIdleTTL = 10 * time.Minute

// UsageReader is the slice of the usage rollup billing needs: a tenant's
// current-period and arbitrary-period rows. It is satisfied by *usage.Store and
// is the SAME rollup the meter writes — billing introduces no second source of
// truth for consumption. Defined as an interface so the service is testable with
// a fake.
type UsageReader interface {
	GetCurrentUsage(ctx context.Context, workspaceID uuid.UUID) ([]usage.TenantUsage, error)
	GetUsage(ctx context.Context, workspaceID uuid.UUID, period string) ([]usage.TenantUsage, error)
}

// PlanStore is the plan persistence the service needs, satisfied by *Store.
type PlanStore interface {
	PlanFor(ctx context.Context, workspaceID uuid.UUID) (Plan, error)
	SetPlan(ctx context.Context, p TenantPlan) error
}

// Config tunes the Service.
type Config struct {
	// EnforceHardCap controls whether a HARD-exceeded decision actually denies
	// the request. When true, over-the-hard-ceiling requests are rejected (402).
	// When false (the default "shadow" posture), the breach is still detected,
	// surfaced via headers, and metered, but the request is ALLOWED — so an
	// operator can roll the feature out by observing who WOULD be capped before
	// flipping enforcement on, avoiding a surprise mass-rejection at 5,000
	// tenants.
	EnforceHardCap bool
	// CacheTTL is how long a per-workspace decision is reused before a refresh.
	// Non-positive uses defaultCacheTTL.
	CacheTTL time.Duration
	// IdleTTL is how long an unused cache entry survives before eviction.
	// Non-positive uses defaultIdleTTL.
	IdleTTL time.Duration
	// now is injectable so tests can drive the cache clock deterministically; it
	// defaults to time.Now.
	now func() time.Time
}

// QuotaState classifies a tenant's consumption against its plan for a metric.
type QuotaState int

const (
	// QuotaOK means consumption is within the included quota.
	QuotaOK QuotaState = iota
	// QuotaSoftExceeded means consumption is over the included quota but under
	// the hard ceiling: allowed, but flagged (a soft warning) and billed as
	// overage.
	QuotaSoftExceeded
	// QuotaHardExceeded means consumption is at or above the hard ceiling.
	QuotaHardExceeded
)

// String renders the state for headers/JSON ("ok"/"soft_exceeded"/"hard_exceeded").
func (s QuotaState) String() string {
	switch s {
	case QuotaOK:
		return "ok"
	case QuotaSoftExceeded:
		return "soft_exceeded"
	case QuotaHardExceeded:
		return "hard_exceeded"
	default:
		return "ok"
	}
}

// QuotaDecision is the enforcement verdict for one request. Deny is true ONLY
// when the worst metric is hard-exceeded AND hard enforcement is enabled, so the
// middleware can stay a thin policy-free check: it denies iff Deny. The metric
// fields describe the worst offending metric for the warning/deny response.
type QuotaDecision struct {
	State    QuotaState
	Deny     bool
	Metric   string
	Plan     string
	Used     int64
	Included int64
	HardCap  int64
}

// Allowed reports whether the request may proceed. It is the negation of Deny,
// exposed as a method so call sites read intent rather than a bare bool.
func (d QuotaDecision) Allowed() bool { return !d.Deny }

type cacheEntry struct {
	decision   QuotaDecision
	computedAt time.Time
	lastSeen   time.Time
}

// Service is the billing economics surface: it resolves plans, generates
// statements from the usage rollup, and answers TTL-cached quota-enforcement
// decisions. It is concurrency-safe and runs a background janitor (started by
// NewService) that evicts idle cache entries; call Stop to release it.
type Service struct {
	plans PlanStore
	usage UsageReader
	cfg   Config

	ttl     time.Duration
	idleTTL time.Duration
	now     func() time.Time

	mu      sync.Mutex
	entries map[uuid.UUID]*cacheEntry

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
}

// NewService wires the service over a plan store and the usage reader, applying
// config defaults, and starts the cache janitor.
func NewService(plans PlanStore, reader UsageReader, cfg Config) *Service {
	now := cfg.now
	if now == nil {
		now = time.Now
	}
	ttl := cfg.CacheTTL
	if ttl <= 0 {
		ttl = defaultCacheTTL
	}
	idle := cfg.IdleTTL
	if idle <= 0 {
		idle = defaultIdleTTL
	}
	s := &Service{
		plans:   plans,
		usage:   reader,
		cfg:     cfg,
		ttl:     ttl,
		idleTTL: idle,
		now:     now,
		entries: make(map[uuid.UUID]*cacheEntry),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	go s.janitor()
	return s
}

// PlanFor returns the resolved plan for a workspace (passthrough to the store).
func (s *Service) PlanFor(ctx context.Context, workspaceID uuid.UUID) (Plan, error) {
	return s.plans.PlanFor(ctx, workspaceID)
}

// SetPlan assigns a workspace's plan and invalidates its cached decision so the
// new plan takes effect on the next request rather than after the TTL.
func (s *Service) SetPlan(ctx context.Context, p TenantPlan) error {
	if err := s.plans.SetPlan(ctx, p); err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.entries, p.WorkspaceID)
	s.mu.Unlock()
	return nil
}

// CurrentStatement generates the statement for the workspace's current billing
// period.
func (s *Service) CurrentStatement(ctx context.Context, workspaceID uuid.UUID) (Statement, error) {
	return s.StatementFor(ctx, workspaceID, usage.PeriodOf(s.now()))
}

// StatementFor generates the statement for a specific period. It is
// deterministic and idempotent: it reads the immutable rollup rows for the
// period and the tenant's plan and computes integer line items, so a closed
// period always yields the same statement.
func (s *Service) StatementFor(ctx context.Context, workspaceID uuid.UUID, period string) (Statement, error) {
	if workspaceID == uuid.Nil {
		return Statement{}, errors.New("billing: StatementFor: empty workspace id")
	}
	if period == "" {
		return Statement{}, errors.New("billing: StatementFor: empty period")
	}
	plan, err := s.plans.PlanFor(ctx, workspaceID)
	if err != nil {
		return Statement{}, err
	}
	rows, err := s.usage.GetUsage(ctx, workspaceID, period)
	if err != nil {
		return Statement{}, fmt.Errorf("billing: statement usage read: %w", err)
	}
	return generateStatement(workspaceID, period, plan, rows), nil
}

// MetricStatus is one metric's live quota status for the plan read endpoint.
type MetricStatus struct {
	Metric   string `json:"metric"`
	Used     int64  `json:"used"`
	Included int64  `json:"included"`
	HardCap  int64  `json:"hard_cap"`
	State    string `json:"state"`
}

// PlanStatus is the tenant-facing view of its plan and current-period quota
// consumption, returned by GET /billing/plan.
type PlanStatus struct {
	WorkspaceID       uuid.UUID      `json:"workspace_id"`
	Period            string         `json:"period"`
	Plan              string         `json:"plan"`
	Currency          string         `json:"currency"`
	BasePriceMinor    int64          `json:"base_price_minor"`
	EnforcementActive bool           `json:"enforcement_active"`
	Metrics           []MetricStatus `json:"metrics"`
}

// QuotaStatus reports the workspace's plan and its current-period consumption
// per metric. It is a live read (not the enforcement cache) because the read
// endpoint should reflect the freshest rollup, and is keyed off the same plan +
// rollup the enforcement path uses.
func (s *Service) QuotaStatus(ctx context.Context, workspaceID uuid.UUID) (PlanStatus, error) {
	if workspaceID == uuid.Nil {
		return PlanStatus{}, errors.New("billing: QuotaStatus: empty workspace id")
	}
	period := usage.PeriodOf(s.now())
	plan, err := s.plans.PlanFor(ctx, workspaceID)
	if err != nil {
		return PlanStatus{}, err
	}
	rows, err := s.usage.GetUsage(ctx, workspaceID, period)
	if err != nil {
		return PlanStatus{}, fmt.Errorf("billing: quota status usage read: %w", err)
	}
	used := make(map[string]int64, len(rows))
	for _, r := range rows {
		used[r.Metric] += r.Count
	}
	metrics := make([]string, 0, len(plan.Metrics))
	for m := range plan.Metrics {
		metrics = append(metrics, m)
	}
	sort.Strings(metrics)
	out := PlanStatus{
		WorkspaceID:       workspaceID,
		Period:            period,
		Plan:              plan.Plan,
		Currency:          Currency,
		BasePriceMinor:    plan.BasePriceMinor,
		EnforcementActive: s.cfg.EnforceHardCap,
		Metrics:           make([]MetricStatus, 0, len(metrics)),
	}
	for _, m := range metrics {
		q := plan.Metrics[m]
		state, _, _, _ := classify(q, used[m])
		out.Metrics = append(out.Metrics, MetricStatus{
			Metric:   m,
			Used:     used[m],
			Included: q.Included,
			HardCap:  q.HardCap,
			State:    state.String(),
		})
	}
	return out, nil
}

// Decide returns the TTL-cached quota-enforcement decision for a workspace. On a
// cache miss (or expiry) it loads the plan and the current-period rollup ONCE,
// evaluates the worst metric, caches the verdict for CacheTTL, and returns it;
// within the TTL the call is a pure in-memory map read, so enforcement adds no
// per-request DB load. An error from either lookup is returned to the caller —
// the middleware is fail-open and allows the request on error, so a billing
// outage never takes the API down.
func (s *Service) Decide(ctx context.Context, workspaceID uuid.UUID) (QuotaDecision, error) {
	if workspaceID == uuid.Nil {
		return QuotaDecision{}, errors.New("billing: Decide: empty workspace id")
	}
	now := s.now()
	s.mu.Lock()
	if e, ok := s.entries[workspaceID]; ok {
		e.lastSeen = now
		if now.Sub(e.computedAt) < s.ttl {
			d := e.decision
			s.mu.Unlock()
			return d, nil
		}
	}
	s.mu.Unlock()

	// Cache miss/expiry: load outside the lock so one tenant's DB read never
	// blocks every other tenant's enforcement check. A rare concurrent
	// double-load for the same workspace is harmless (idempotent reads).
	decision, err := s.evaluate(ctx, workspaceID)
	if err != nil {
		return QuotaDecision{}, err
	}
	s.mu.Lock()
	s.entries[workspaceID] = &cacheEntry{decision: decision, computedAt: now, lastSeen: now}
	s.mu.Unlock()
	return decision, nil
}

// evaluate loads the plan + current usage and computes the worst-metric verdict.
func (s *Service) evaluate(ctx context.Context, workspaceID uuid.UUID) (QuotaDecision, error) {
	plan, err := s.plans.PlanFor(ctx, workspaceID)
	if err != nil {
		return QuotaDecision{}, err
	}
	rows, err := s.usage.GetCurrentUsage(ctx, workspaceID)
	if err != nil {
		return QuotaDecision{}, fmt.Errorf("billing: decide usage read: %w", err)
	}
	used := make(map[string]int64, len(rows))
	for _, r := range rows {
		used[r.Metric] += r.Count
	}

	// Evaluate metrics in sorted order so the chosen "worst" metric is
	// deterministic when two metrics share the same severity.
	metrics := make([]string, 0, len(plan.Metrics))
	for m := range plan.Metrics {
		metrics = append(metrics, m)
	}
	sort.Strings(metrics)

	decision := QuotaDecision{State: QuotaOK, Plan: plan.Plan}
	for _, m := range metrics {
		q := plan.Metrics[m]
		state, u, included, hardCap := classify(q, used[m])
		if state > decision.State {
			decision.State = state
			decision.Metric = m
			decision.Used = u
			decision.Included = included
			decision.HardCap = hardCap
		}
	}
	decision.Deny = decision.State == QuotaHardExceeded && s.cfg.EnforceHardCap
	return decision, nil
}

// classify compares a used count against a metric's quota, returning the state
// and the (used, included, hardCap) it was judged against. A zero HardCap means
// unlimited, so it can never be hard-exceeded.
func classify(q MetricQuota, used int64) (QuotaState, int64, int64, int64) {
	switch {
	case q.HardCap > 0 && used >= q.HardCap:
		return QuotaHardExceeded, used, q.Included, q.HardCap
	case used > q.Included:
		return QuotaSoftExceeded, used, q.Included, q.HardCap
	default:
		return QuotaOK, used, q.Included, q.HardCap
	}
}

func (s *Service) janitor() {
	defer close(s.done)
	ticker := time.NewTicker(s.idleTTL)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			s.evictIdle(s.now())
		}
	}
}

func (s *Service) evictIdle(now time.Time) {
	cutoff := now.Add(-s.idleTTL)
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.entries {
		if e.lastSeen.Before(cutoff) {
			delete(s.entries, k)
		}
	}
}

// CacheLen returns the number of live cache entries. Exposed for tests and for
// an operator gauge of how many tenants are currently being enforced.
func (s *Service) CacheLen() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// Stop terminates the janitor goroutine. It is idempotent and safe to call from
// a shutdown path.
func (s *Service) Stop() {
	s.stopOnce.Do(func() { close(s.stop) })
	<-s.done
}
