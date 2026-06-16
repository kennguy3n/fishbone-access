// Command bench measures control-plane API latency and throughput against a
// seeded workspace, on whatever machine the blog series is built on. It is the
// fourth blog harness (after seed, capture, minttokens): seed drives state,
// capture reads it back verbatim, minttokens lets a human browse it, and bench
// times it.
//
// It is deliberately honest about what it does and does not measure. It times
// the FULL request path a console user hits — TLS-less HTTP, dev JWT validation
// (HS256), tenant resolution, RBAC, the handler, GORM, and Postgres — over
// loopback on a single dev VM. It is NOT a tuned production benchmark: one API
// process, one Postgres, no server/DB connection-pool tuning, no warm CDN, no
// horizontal scale. The numbers are a floor ("even an untuned dev box does X"),
// not a ceiling, and the blog says so. (The HTTP *client* is given an idle pool
// sized to the concurrency so the figures reflect server latency, not avoidable
// client-side reconnection churn.)
//
// Every endpoint here is a real, RBAC-gated route exercised by the seeded
// Acme Payments (sg/finance) workspace plus the global catalogue reads every
// tenant shares. Read endpoints are looped directly; the one write path
// (policy simulate-definition) exercises the impact/conflict engine without
// persisting anything, so the run stays idempotent and leaves no state.
//
// This measures raw server latency, not the per-tenant rate limiter — those are
// separate properties. The limiter (a deliberate fairness shield, default 50
// rps / 100 burst per tenant) would otherwise shape a single-tenant 400-request
// burst into mostly-429 errors and the timings would reflect rejection speed,
// not work. So start the measured API with ACCESS_TENANT_RATE_LIMIT_ENABLED=false
// for a bench run; the limiter is exercised by its own unit tests. As a guard,
// the bench exits non-zero if any endpoint returns errors, so a throttled or
// otherwise-degraded run can never be silently committed as evidence.
//
// Usage:
//
//	AUTH_JWT_SECRET=... ACCESS_TENANT_RATE_LIMIT_ENABLED=false go run ./blog/harness/bench \
//	  -base http://localhost:8080 -n 400 -c 16 -out blog/artifacts/benchmark-results.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kennguy3n/fishbone-access/blog/harness/harnesskit"
)

var (
	apiBase = flag.String("base", envOr("BLOG_API_BASE", "http://localhost:8080"), "control-plane base URL")
	reqN    = flag.Int("n", 400, "requests per endpoint (after warmup)")
	conc    = flag.Int("c", 16, "concurrent workers per endpoint")
	warmup  = flag.Int("warmup", 30, "warmup requests per endpoint (not measured)")
	outFile = flag.String("out", "blog/artifacts/benchmark-results.json", "results JSON path")
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// chainHead reads the current (chain_seq, chain_hash) head of the bench
// workspace's audit chain from the descending evidence stream, so the bench can
// anchor the incremental verify on a real, current head. Returns (0, "") when
// the workspace has no evidence yet, in which case the incremental target is
// skipped rather than timed against an invalid anchor.
func chainHead(c *harnesskit.Client) (int64, string) {
	var ev struct {
		Records []struct {
			ChainSeq  int64  `json:"chain_seq"`
			ChainHash string `json:"chain_hash"`
		} `json:"records"`
	}
	if !c.JSON("GET", "/api/v1/compliance/evidence?order=desc&limit=1", nil, &ev) || len(ev.Records) == 0 {
		return 0, ""
	}
	return ev.Records[0].ChainSeq, ev.Records[0].ChainHash
}

// target is one endpoint to time. POST targets carry a body; everything else is
// a GET. group buckets the endpoint for the blog's results table.
type target struct {
	Name   string `json:"name"`
	Group  string `json:"group"`
	Method string `json:"method"`
	Path   string `json:"path"`
	body   any
}

// result is the measured latency distribution for one target.
type result struct {
	target
	Requests    int     `json:"requests"`
	Errors      int     `json:"errors"`
	Concurrency int     `json:"concurrency"`
	WallMS      float64 `json:"wall_ms"`
	Throughput  float64 `json:"throughput_rps"`
	MeanMS      float64 `json:"mean_ms"`
	P50MS       float64 `json:"p50_ms"`
	P90MS       float64 `json:"p90_ms"`
	P99MS       float64 `json:"p99_ms"`
	MaxMS       float64 `json:"max_ms"`
}

type report struct {
	GeneratedAt time.Time         `json:"generated_at"`
	APIBase     string            `json:"api_base"`
	Workspace   string            `json:"workspace"`
	RequestsPer int               `json:"requests_per_endpoint"`
	Concurrency int               `json:"concurrency"`
	System      map[string]string `json:"system"`
	Results     []result          `json:"results"`
}

func main() {
	flag.Parse()
	secret := os.Getenv("AUTH_JWT_SECRET")
	if secret == "" {
		harnesskit.Fatalf("AUTH_JWT_SECRET must be set (the dev HMAC signing secret)")
	}

	// Bench the flagship workspace (sg/finance) — it has the richest seeded
	// state (4 connectors, 6 active policies, PAM targets/leases, campaigns).
	var ws harnesskit.Workspace
	for _, w := range harnesskit.Workspaces {
		if w.Slug == "sg-acme-payments" {
			ws = w
		}
	}
	if ws.Slug == "" {
		ws = harnesskit.Workspaces[0]
	}
	token := harnesskit.MintJWT(secret, harnesskit.DefaultIssuer, harnesskit.DefaultAudience,
		ws.OwnerSub(), ws.TenantID, ws.OwnerRoles(), true, time.Hour)
	c := harnesskit.NewClient(*apiBase, token, false)
	// Give the benchmark a connection pool sized to its concurrency so we measure
	// server-side latency, not avoidable client-side connection churn. The stock
	// transport caps MaxIdleConnsPerHost at 2, which would force most of the c
	// workers to re-dial on every request and inflate the numbers.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConns = *conc
	tr.MaxIdleConnsPerHost = *conc
	tr.MaxConnsPerHost = *conc
	c.HTTP.Transport = tr

	simDef := map[string]any{"definition": map[string]any{
		"action": "grant", "subjects": []string{"user:bench@demo.test"}, "resources": []string{"app:bench"},
	}}

	targets := []target{
		{Name: "health", Group: "liveness", Method: "GET", Path: "/health"},
		{Name: "list-policies", Group: "govern", Method: "GET", Path: "/api/v1/policies"},
		{Name: "list-packs (region)", Group: "govern", Method: "GET", Path: "/api/v1/packs?region=" + ws.Region},
		{Name: "list-providers (200+)", Group: "catalogue", Method: "GET", Path: "/api/v1/connectors/providers"},
		{Name: "catalogue-facets", Group: "catalogue", Method: "GET", Path: "/api/v1/connectors/catalogue/facets"},
		{Name: "list-access-requests", Group: "lifecycle", Method: "GET", Path: "/api/v1/access-requests"},
		{Name: "list-connectors", Group: "lifecycle", Method: "GET", Path: "/api/v1/connectors"},
		{Name: "pam-targets", Group: "pam", Method: "GET", Path: "/api/v1/pam/targets"},
		{Name: "pam-leases", Group: "pam", Method: "GET", Path: "/api/v1/pam/leases"},
		{Name: "connector-agents", Group: "pam", Method: "GET", Path: "/api/v1/agents"},
		{Name: "discovery-summary", Group: "pam", Method: "GET", Path: "/api/v1/discovery/summary"},
		{Name: "rotation-policies", Group: "pam", Method: "GET", Path: "/api/v1/pam/rotation/policies"},
		{Name: "recordings-search", Group: "pam", Method: "GET", Path: "/api/v1/pam/recordings"},
		{Name: "compliance-coverage (SOC2)", Group: "compliance", Method: "GET", Path: "/api/v1/compliance/coverage?framework=SOC%202"},
		{Name: "chain-verify", Group: "compliance", Method: "GET", Path: "/api/v1/compliance/chain/verify"},
		{Name: "evidence-timeline", Group: "compliance", Method: "GET", Path: "/api/v1/compliance/evidence"},
		{Name: "policy-simulate (engine)", Group: "engine", Method: "POST", Path: "/api/v1/policies/simulate-definition", body: simDef},
	}

	// Time the O(Δ) incremental verify alongside the full O(n) chain-verify, on
	// the SAME route and workspace. The anchor is the current chain head, so the
	// timed call re-verifies zero new rows — the cheap re-verify a long-lived
	// dashboard runs once it holds a baseline. The contrast with chain-verify is
	// the whole point of the optimisation at 5,000-tenant scale, so we measure
	// both rather than asserting the saving.
	if headSeq, headHash := chainHead(c); headHash != "" {
		targets = append(targets, target{
			Name: "chain-verify-incremental", Group: "compliance", Method: "GET",
			Path: fmt.Sprintf("/api/v1/compliance/chain/verify?from_seq=%d&from_hash=%s", headSeq, headHash),
		})
	}

	rep := report{
		GeneratedAt: time.Now().UTC(),
		APIBase:     *apiBase,
		Workspace:   ws.Slug,
		RequestsPer: *reqN,
		Concurrency: *conc,
		System:      systemInfo(),
	}

	fmt.Printf("benchmark — %s @ %s · n=%d c=%d\n", ws.Slug, *apiBase, *reqN, *conc)
	fmt.Printf("%-30s %8s %8s %8s %8s %8s %10s %7s\n", "endpoint", "p50ms", "p90ms", "p99ms", "max", "mean", "req/s", "errs")
	for _, t := range targets {
		r := run(c, t, *reqN, *conc, *warmup)
		rep.Results = append(rep.Results, r)
		fmt.Printf("%-30s %8.2f %8.2f %8.2f %8.2f %8.2f %10.0f %7d\n",
			trunc(t.Name, 30), r.P50MS, r.P90MS, r.P99MS, r.MaxMS, r.MeanMS, r.Throughput, r.Errors)
	}

	if err := writeJSON(*outFile, rep); err != nil {
		harnesskit.Fatalf("write %s: %v", *outFile, err)
	}
	fmt.Printf("\nwrote %s\n", *outFile)

	// Guard the evidence: a healthy localhost bench against a seeded workspace
	// should return zero non-2xx responses. Any errors mean the run is degraded
	// (most commonly the per-tenant rate limiter throttling the burst into 429s,
	// or a half-seeded workspace) and the artifact would misrepresent the system
	// as failing under trivial load. Fail loudly so it is never committed.
	var degraded []string
	for _, r := range rep.Results {
		if r.Errors > 0 {
			degraded = append(degraded, fmt.Sprintf("%s (%d/%d)", r.Name, r.Errors, r.Requests))
		}
	}
	if len(degraded) > 0 {
		harnesskit.Fatalf("benchmark degraded — %d endpoint(s) returned errors: %s\n"+
			"start the measured API with ACCESS_TENANT_RATE_LIMIT_ENABLED=false and ensure the workspace is seeded",
			len(degraded), strings.Join(degraded, ", "))
	}
}

// run warms the endpoint, then fires n requests across c workers and records
// each request's wall latency. A non-2xx (or transport error) counts as an
// error but its latency is still recorded so a degraded endpoint can't look
// fast by dropping its slow samples.
func run(c *harnesskit.Client, t target, n, conc, warmup int) result {
	for i := 0; i < warmup; i++ {
		_, _, _ = c.Request(t.Method, t.Path, t.body, nil)
	}

	lat := make([]float64, n)
	var errs int64
	var idx int64 = -1
	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := atomic.AddInt64(&idx, 1)
				if int(i) >= n {
					return
				}
				t0 := time.Now()
				status, _, err := c.Request(t.Method, t.Path, t.body, nil)
				lat[i] = float64(time.Since(t0).Microseconds()) / 1000.0
				if err != nil || status < 200 || status >= 300 {
					atomic.AddInt64(&errs, 1)
				}
			}
		}()
	}
	wg.Wait()
	wall := time.Since(start)

	sort.Float64s(lat)
	var sum float64
	for _, v := range lat {
		sum += v
	}
	return result{
		target:      t,
		Requests:    n,
		Errors:      int(errs),
		Concurrency: conc,
		WallMS:      float64(wall.Microseconds()) / 1000.0,
		Throughput:  float64(n) / wall.Seconds(),
		MeanMS:      sum / float64(n),
		P50MS:       pct(lat, 50),
		P90MS:       pct(lat, 90),
		P99MS:       pct(lat, 99),
		MaxMS:       lat[n-1],
	}
}

func pct(sorted []float64, p int) float64 {
	if len(sorted) == 0 {
		return 0
	}
	i := (p * len(sorted)) / 100
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func writeJSON(path string, v any) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func systemInfo() map[string]string {
	info := map[string]string{
		"go_version": runtime.Version(),
		"goos":       runtime.GOOS,
		"goarch":     runtime.GOARCH,
		"num_cpu":    fmt.Sprintf("%d", runtime.NumCPU()),
		"gomaxprocs": fmt.Sprintf("%d", runtime.GOMAXPROCS(0)),
	}
	if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "model name") {
				if p := strings.SplitN(line, ":", 2); len(p) == 2 {
					info["cpu_model"] = strings.TrimSpace(p[1])
					break
				}
			}
		}
	}
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "MemTotal") {
				info["mem_total"] = strings.TrimSpace(strings.TrimPrefix(line, "MemTotal:"))
				break
			}
		}
	}
	return info
}
