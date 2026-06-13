// Command capture saves real fishbone-access control-plane API responses to
// blog/artifacts/payloads/ for use as evidence in the blog series.
//
// It reads blog/artifacts/seed-summary.json (written by the seed harness) to
// learn each workspace's tenant id and the ids the detail endpoints need
// (review id, campaign id, connector ids), mints the SAME per-workspace HS256
// token the seed used (so the control plane's dev validator resolves the same
// workspace + RBAC), GETs a fixed set of scenario-relevant endpoints, and
// writes each response as pretty-printed JSON. It also drives the step-up-gated
// evidence-pack export (POST /compliance/export) for two workspaces, saving the
// returned ZIP verbatim and the manifest.json extracted from it.
//
// Every file under payloads/ is therefore a verbatim capture of a live request
// against the seeded stack — never hand-authored. Re-running against the same
// seeded data reproduces the same files (the export ZIP's embedded timestamps
// aside).
//
// Usage:
//
//	AUTH_JWT_SECRET=... go run ./blog/harness/capture \
//	  -base http://localhost:8080 -out blog/artifacts/payloads \
//	  -summary blog/artifacts/seed-summary.json
package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/kennguy3n/fishbone-access/blog/harness/harnesskit"
)

// exportSpec parameterises one evidence-pack export capture. Framework must be
// one of the server's ValidFramework values ("SOC 2", "ISO 27001", "PCI-DSS").
type exportSpec struct {
	slug      string
	framework string
}

// frameworks are the server's ValidFramework values paired with a file-safe
// token for the coverage artifact name. Coverage is computed for every
// framework against each workspace's evidence, so a workspace's coverage under a
// framework it did not adopt is an honest near-empty map — exactly the
// multi-framework story scenario S3 (German retail) tells.
var frameworks = []struct {
	query string // server-side ValidFramework value
	token string // file-safe artifact token
}{
	{query: "PCI-DSS", token: "pci-dss"},
	{query: "ISO 27001", token: "iso27001"},
	{query: "SOC 2", token: "soc2"},
}

func main() {
	var (
		base        = flag.String("base", envOr("BLOG_API_BASE", "http://localhost:8080"), "control-plane API base URL")
		out         = flag.String("out", "blog/artifacts/payloads", "output directory for captured payloads")
		summaryPath = flag.String("summary", "blog/artifacts/seed-summary.json", "path to seed-summary.json")
		verbose     = flag.Bool("verbose", false, "log every request")
	)
	flag.Parse()

	secret := os.Getenv("AUTH_JWT_SECRET")
	if secret == "" {
		harnesskit.Fatalf("AUTH_JWT_SECRET is required (same secret the control plane verifies)")
	}
	issuer := envOr("AUTH_JWT_ISSUER", harnesskit.DefaultIssuer)
	audience := envOr("AUTH_JWT_AUDIENCE", harnesskit.DefaultAudience)

	summary, err := loadSummary(*summaryPath)
	if err != nil {
		harnesskit.Fatalf("load seed summary %s: %v (run the seed harness first)", *summaryPath, err)
	}
	if len(summary.Workspaces) == 0 {
		harnesskit.Fatalf("seed summary has no workspaces — run the seed harness first")
	}
	if err := os.MkdirAll(*out, 0o750); err != nil {
		harnesskit.Fatalf("mkdir %s: %v", *out, err)
	}

	cap := &capturer{out: *out, ok: 0, fail: 0, skip: 0}

	// Per-workspace captures: each file is prefixed s{index}-{slug}- so the blog
	// posts can reference an unambiguous, scenario-tagged artifact.
	for _, ws := range summary.Workspaces {
		token := harnesskit.MintJWT(secret, issuer, audience, ownerSub(ws.Slug), ws.TenantID, []string{"owner"}, true, time.Hour)
		c := harnesskit.NewClient(*base, token, *verbose)
		prefix := "s" + strconv.Itoa(ws.Index) + "-" + ws.Slug + "-"

		cap.get(c, prefix+"packs", "/api/v1/packs?region="+ws.Region)
		cap.get(c, prefix+"policies", "/api/v1/policies")
		cap.get(c, prefix+"requests", "/api/v1/access-requests")
		cap.get(c, prefix+"connectors", "/api/v1/connectors")
		cap.get(c, prefix+"catalogue-facets", "/api/v1/connectors/catalogue/facets")
		cap.get(c, prefix+"orphans", "/api/v1/orphan-accounts")
		cap.get(c, prefix+"evidence", "/api/v1/compliance/evidence")
		// Coverage is framework-scoped (the endpoint 400s without a valid
		// ?framework=). Capture all three so the blog can show coverage across
		// frameworks for one workspace's evidence.
		for _, fw := range frameworks {
			cap.get(c, prefix+"coverage-"+fw.token, "/api/v1/compliance/coverage?framework="+url.QueryEscape(fw.query))
		}
		cap.get(c, prefix+"chain-verify", "/api/v1/compliance/chain/verify")
		cap.chainIncremental(c, prefix)
		cap.get(c, prefix+"campaigns", "/api/v1/compliance/campaigns")

		// Detail endpoints need ids the seed recorded; skip (not fail) when a
		// workspace didn't produce one.
		if id := ws.IDs.ReviewID; id != "" {
			cap.get(c, prefix+"review-report", "/api/v1/access-reviews/"+id)
			cap.get(c, prefix+"review-items", "/api/v1/access-reviews/"+id+"/items")
		} else {
			cap.skipf(prefix + "review-report/items (no review id in summary)")
		}
		if id := ws.IDs.CampaignID; id != "" {
			cap.get(c, prefix+"campaign-report", "/api/v1/compliance/campaigns/"+id)
		} else {
			cap.skipf(prefix + "campaign-report (no campaign id in summary)")
		}
		if id := connectorForSSO(ws.IDs); id != "" {
			cap.get(c, prefix+"sso-status", "/api/v1/connectors/"+id+"/sso-status")
		} else {
			cap.skipf(prefix + "sso-status (no connector id in summary)")
		}

		// New-journey captures: PAM (privileged targets + JIT leases +
		// sessions), contractor/external access, and the separation-of-duties
		// rule set + detected anomalies.
		cap.get(c, prefix+"pam-targets", "/api/v1/pam/targets")
		cap.get(c, prefix+"pam-leases", "/api/v1/pam/leases")
		cap.get(c, prefix+"pam-sessions", "/api/v1/pam/sessions")
		cap.get(c, prefix+"contractor-grants", "/api/v1/contractor-grants")
		cap.get(c, prefix+"sod-rules", "/api/v1/sod-rules")
		cap.get(c, prefix+"sod-anomalies", "/api/v1/sod-anomalies")

		// SoD access simulation: replay the dry-run that would hand ONE subject
		// both halves of the workspace's first toxic-combination rule, capturing
		// the verdict the engine returns (the conflict/violation it blocks
		// *before* any grant is made). The verdict lives only in the response.
		var sod struct {
			Rules []struct {
				ResourceA string `json:"resource_a"`
				RoleA     string `json:"role_a"`
				ResourceB string `json:"resource_b"`
			} `json:"rules"`
		}
		if c.JSON("GET", "/api/v1/sod-rules", nil, &sod) && len(sod.Rules) > 0 {
			r := sod.Rules[0]
			def := map[string]any{
				"action":    "grant",
				"subjects":  []string{ownerSub(ws.Slug)},
				"resources": []string{r.ResourceA, r.ResourceB},
				"role":      r.RoleA,
			}
			cap.post(c, prefix+"sod-simulation", "/api/v1/policies/simulate-definition", map[string]any{"definition": def})
		} else {
			cap.skipf(prefix + "sod-simulation (no sod rules in workspace)")
		}

		// AI-assisted risk assessment: the access-request detail endpoint
		// returns the request alongside the control plane's risk verdict and
		// advisory anomaly flags. Walk the requests and capture the first detail
		// that actually carries a "risk" verdict (the SCIM-driven JML requests
		// have none), so the blog shows a real verdict payload.
		var reqs struct {
			Requests []struct {
				ID string `json:"id"`
			} `json:"requests"`
		}
		captured := false
		if c.JSON("GET", "/api/v1/access-requests", nil, &reqs) {
			for _, r := range reqs.Requests {
				var detail map[string]json.RawMessage
				if c.JSON("GET", "/api/v1/access-requests/"+r.ID, nil, &detail) {
					if _, hasRisk := detail["risk"]; hasRisk {
						cap.get(c, prefix+"request-risk", "/api/v1/access-requests/"+r.ID)
						captured = true
						break
					}
				}
			}
		}
		if !captured {
			cap.skipf(prefix + "request-risk (no request carries a risk verdict)")
		}
	}

	// Global captures (once): the catalogue surface and the full pack catalog by
	// tier. These are tenant-agnostic, so the first workspace's token suffices.
	g := harnesskit.NewClient(*base, harnesskit.MintJWT(secret, issuer, audience, ownerSub(summary.Workspaces[0].Slug), summary.Workspaces[0].TenantID, []string{"owner"}, true, time.Hour), *verbose)
	cap.get(g, "global-providers", "/api/v1/connectors/providers")
	cap.get(g, "global-packs-all", "/api/v1/packs")
	cap.get(g, "global-packs-tier1", "/api/v1/packs?tier=1")
	cap.get(g, "global-packs-tier2", "/api/v1/packs?tier=2")
	cap.get(g, "global-packs-tier3", "/api/v1/packs?tier=3")

	// Evidence-pack export (POST, step-up-gated) for two workspaces with two
	// different frameworks: Acme Payments (SG) under PCI-DSS and Contoso SaaS
	// (AU) under SOC 2. The ZIP is saved verbatim and its manifest.json is
	// extracted so the blog can show both the deliverable and its content
	// digest / chain status without unzipping by hand.
	exports := []exportSpec{
		{slug: "sg-acme-payments", framework: "PCI-DSS"},
		{slug: "au-contoso-saas", framework: "SOC 2"},
	}
	for _, e := range exports {
		ws, ok := findWorkspace(summary, e.slug)
		if !ok {
			cap.skipf("export %s (workspace not in summary)", e.slug)
			continue
		}
		token := harnesskit.MintJWT(secret, issuer, audience, ownerSub(ws.Slug), ws.TenantID, []string{"owner"}, true, time.Hour)
		c := harnesskit.NewClient(*base, token, *verbose)
		disp := harnesskit.NewStepUpDispenser(harnesskit.TOTPBase32Secret(ws.Slug))
		prefix := "s" + strconv.Itoa(ws.Index) + "-" + ws.Slug + "-"
		cap.exportPack(c, disp, prefix, e.framework)
	}

	harnesskit.Logf("\ncaptured %d ok, %d skipped, %d failed", cap.ok, cap.skip, cap.fail)
	if cap.fail > 0 {
		os.Exit(1)
	}
}

// capturer accumulates write results and centralises the pretty-print + write.
type capturer struct {
	out            string
	ok, fail, skip int
}

// get issues a GET, pretty-prints the JSON body, and writes it to name.json. A
// non-2xx or non-JSON body is a FAIL (the seeded stack should answer every
// listed endpoint); an empty collection is still valid JSON and captured as-is.
func (cp *capturer) get(c *harnesskit.Client, name, path string) {
	status, raw, err := c.Request("GET", path, nil, nil)
	if err != nil {
		harnesskit.Logf("FAIL %-44s %v", name, err)
		cp.fail++
		return
	}
	if status < 200 || status >= 300 {
		harnesskit.Logf("FAIL %-44s HTTP %d: %s", name, status, truncate(raw, 200))
		cp.fail++
		return
	}
	pretty, perr := prettyJSON(raw)
	if perr != nil {
		harnesskit.Logf("FAIL %-44s non-JSON response: %v", name, perr)
		cp.fail++
		return
	}
	dst := filepath.Join(cp.out, name+".json")
	if err := os.WriteFile(dst, pretty, 0o600); err != nil {
		harnesskit.Logf("FAIL %-44s write: %v", name, err)
		cp.fail++
		return
	}
	harnesskit.Logf("OK   %-44s HTTP %d  %d bytes -> %s", name, status, len(pretty), dst)
	cp.ok++
}

// post issues a POST with a JSON body and captures the (pretty-printed)
// response. Used for read-only, idempotent dry-runs whose verdict only lives in
// the response body (e.g. the SoD access simulation), never for state changes.
func (cp *capturer) post(c *harnesskit.Client, name, path string, body any) {
	status, raw, err := c.Request("POST", path, body, nil)
	if err != nil {
		harnesskit.Logf("FAIL %-44s %v", name, err)
		cp.fail++
		return
	}
	if status < 200 || status >= 300 {
		harnesskit.Logf("FAIL %-44s HTTP %d: %s", name, status, truncate(raw, 200))
		cp.fail++
		return
	}
	pretty, perr := prettyJSON(raw)
	if perr != nil {
		harnesskit.Logf("FAIL %-44s non-JSON response: %v", name, perr)
		cp.fail++
		return
	}
	dst := filepath.Join(cp.out, name+".json")
	if err := os.WriteFile(dst, pretty, 0o600); err != nil {
		harnesskit.Logf("FAIL %-44s write: %v", name, err)
		cp.fail++
		return
	}
	harnesskit.Logf("OK   %-44s HTTP %d  %d bytes -> %s", name, status, len(pretty), dst)
	cp.ok++
}

// exportPack POSTs the step-up-gated evidence-pack export, saves the returned
// ZIP verbatim, and extracts manifest.json from it. A fresh TOTP assertion is
// attached per attempt; the dispenser never reuses a code (anti-replay).
func (cp *capturer) exportPack(c *harnesskit.Client, disp *harnesskit.StepUpDispenser, prefix, framework string) {
	name := prefix + "evidence-pack"
	body := map[string]any{"framework": framework}
	status, raw, err := c.Request("POST", "/api/v1/compliance/export", body,
		map[string]string{harnesskit.StepUpHeader: disp.Next()})
	if err != nil {
		harnesskit.Logf("FAIL %-44s %v", name, err)
		cp.fail++
		return
	}
	if status < 200 || status >= 300 {
		harnesskit.Logf("FAIL %-44s HTTP %d: %s", name, status, truncate(raw, 200))
		cp.fail++
		return
	}
	zipPath := filepath.Join(cp.out, name+".zip")
	if err := os.WriteFile(zipPath, raw, 0o600); err != nil {
		harnesskit.Logf("FAIL %-44s write zip: %v", name, err)
		cp.fail++
		return
	}
	harnesskit.Logf("OK   %-44s HTTP %d  %d bytes -> %s", name, status, len(raw), zipPath)
	cp.ok++

	// Extract manifest.json so the blog can cite the content digest / chain
	// status directly. A missing manifest is a real failure (the pack format
	// changed), not a skip.
	manifest, err := extractZipEntry(raw, "manifest.json")
	if err != nil {
		harnesskit.Logf("FAIL %-44s extract manifest: %v", name+"-manifest", err)
		cp.fail++
		return
	}
	pretty, perr := prettyJSON(manifest)
	if perr != nil {
		harnesskit.Logf("FAIL %-44s manifest not JSON: %v", name+"-manifest", perr)
		cp.fail++
		return
	}
	dst := filepath.Join(cp.out, name+"-manifest.json")
	if err := os.WriteFile(dst, pretty, 0o600); err != nil {
		harnesskit.Logf("FAIL %-44s write manifest: %v", name+"-manifest", err)
		cp.fail++
		return
	}
	harnesskit.Logf("OK   %-44s          %d bytes -> %s", name+"-manifest", len(pretty), dst)
	cp.ok++
}

// chainIncremental captures the O(Δ) incremental ("consistency") verify added
// for 5,000-tenant scale. It reads the current chain head and an earlier anchor
// from the evidence stream (descending), then GETs the SAME verify route with
// from_seq/from_hash set: once FROM the head (no rows after it -> "consistent",
// verified 0 — the cheap re-verify a dashboard runs on every load) and once
// FROM the earlier anchor (verifies only the suffix window). Both are verbatim
// responses, so the blog can show that the incremental path re-checks a handful
// of rows where the full verify re-walks the whole chain.
func (cp *capturer) chainIncremental(c *harnesskit.Client, prefix string) {
	var ev struct {
		Records []struct {
			ChainSeq  int64  `json:"chain_seq"`
			ChainHash string `json:"chain_hash"`
		} `json:"records"`
	}
	if !c.JSON("GET", "/api/v1/compliance/evidence?order=desc&limit=8", nil, &ev) || len(ev.Records) == 0 {
		cp.skipf(prefix + "chain-verify-incremental (no evidence to anchor on)")
		return
	}
	head := ev.Records[0]
	cp.get(c, prefix+"chain-verify-incremental-head",
		fmt.Sprintf("/api/v1/compliance/chain/verify?from_seq=%d&from_hash=%s", head.ChainSeq, head.ChainHash))

	// The oldest row in the descending window is an earlier trusted anchor; a
	// verify from it re-checks only the rows newer than it.
	anchor := ev.Records[len(ev.Records)-1]
	if anchor.ChainSeq != head.ChainSeq {
		cp.get(c, prefix+"chain-verify-incremental-window",
			fmt.Sprintf("/api/v1/compliance/chain/verify?from_seq=%d&from_hash=%s", anchor.ChainSeq, anchor.ChainHash))
	} else {
		cp.skipf(prefix + "chain-verify-incremental-window (chain too short for a window)")
	}
}

func (cp *capturer) skipf(format string, args ...any) {
	harnesskit.Logf("SKIP "+format, args...)
	cp.skip++
}

// extractZipEntry returns the bytes of the named entry from an in-memory ZIP.
func extractZipEntry(zipBytes []byte, name string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		if f.Name != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		// Read and close in the loop body (no deferred close accumulating across
		// iterations); we return immediately, so the entry is closed before the
		// function exits regardless of the read outcome.
		data, readErr := io.ReadAll(rc)
		if cerr := rc.Close(); cerr != nil && readErr == nil {
			readErr = cerr
		}
		return data, readErr
	}
	return nil, os.ErrNotExist
}

func loadSummary(path string) (harnesskit.Summary, error) {
	var s harnesskit.Summary
	// path is an operator-supplied CLI flag pointing at the seed harness's own
	// output (seed-summary.json); this is a local dev/evidence tool, not a
	// network service, so reading the given path is the intended behaviour.
	b, err := os.ReadFile(path) //nolint:gosec // operator-supplied path to seed-summary.json in a dev harness; not a network-reachable input
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, err
	}
	return s, nil
}

func findWorkspace(s harnesskit.Summary, slug string) (harnesskit.WorkspaceSummary, bool) {
	for _, ws := range s.Workspaces {
		if ws.Slug == slug {
			return ws, true
		}
	}
	return harnesskit.WorkspaceSummary{}, false
}

// connectorForSSO picks the connector to query SSO status for: the manual
// target if present (always seeded), else the first connector id.
func connectorForSSO(ids harnesskit.WorkspaceIDs) string {
	if ids.ManualConnector != "" {
		return ids.ManualConnector
	}
	if len(ids.ConnectorIDs) > 0 {
		return ids.ConnectorIDs[0]
	}
	return ""
}

// ownerSub mirrors harnesskit.Workspace.OwnerSub for a slug (the seed minted
// tokens for "{slug}-owner"); duplicated here to avoid threading a full
// Workspace through the summary.
func ownerSub(slug string) string { return slug + "-owner" }

func prettyJSON(b []byte) ([]byte, error) {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
