// shoot.mjs — the fifth blog harness. Seed drives state, capture reads it back
// verbatim, bench times it, minttokens lets a human browse it, and shoot
// photographs it. It drives a headless Chromium through the real console (the
// Vite dev server proxying to the live control plane) and writes the exact
// screenshot set the blog posts embed.
//
// It is reproducible by construction:
//   - identities come from `minttokens` (same JWT shape the seed uses), passed
//     in via BLOG_TOKENS as a `slug<TAB>region<TAB>token` file;
//   - the per-tenant dynamic IDs (the risk-scored request, the certification
//     campaign) are read from the *committed capture payloads*, so the harness
//     never hard-codes a UUID and always points at whatever was last seeded.
//
// Usage (see `make blog-screenshots`):
//   go run ./blog/harness/minttokens > tokens.tsv
//   BLOG_TOKENS=tokens.tsv node blog/harness/screenshots/shoot.mjs
//
// Env:
//   BLOG_UI_BASE    console base URL              (default http://localhost:5173)
//   BLOG_TOKENS     path to minttokens TSV output (required)
//   BLOG_PAYLOADS   captured payloads directory   (default blog/artifacts/payloads)
//   BLOG_SHOTS_OUT  screenshot output directory   (default blog/artifacts/screenshots)
import { chromium } from "playwright";
import fs from "node:fs";
import path from "node:path";

const BASE = process.env.BLOG_UI_BASE || "http://localhost:5173";
const TOKENS_FILE = process.env.BLOG_TOKENS;
const PAYLOADS = process.env.BLOG_PAYLOADS || "blog/artifacts/payloads";
const OUT = process.env.BLOG_SHOTS_OUT || "blog/artifacts/screenshots";

if (!TOKENS_FILE || !fs.existsSync(TOKENS_FILE)) {
  console.error("BLOG_TOKENS must point at a minttokens TSV (slug<TAB>region<TAB>token).");
  console.error("Generate it with: go run ./blog/harness/minttokens > tokens.tsv");
  process.exit(1);
}
fs.mkdirSync(OUT, { recursive: true });

// Stable workspace metadata, mirroring harnesskit.Workspaces: scenario index,
// region slug used in screenshot filenames, and the payload-file prefix.
const WS = {
  "sg-acme-payments":      { idx: 1, region: "sg" },
  "us-globex-health":      { idx: 2, region: "us" },
  "de-initech-retail":     { idx: 3, region: "de" },
  "vn-umbrella-logistics": { idx: 4, region: "vn" },
  "ae-northwind-finance":  { idx: 5, region: "ae" },
  "au-contoso-saas":       { idx: 6, region: "au" },
};
const shotPrefix = (slug) => `s${WS[slug].idx}-${WS[slug].region}`;
const payloadPrefix = (slug) => `s${WS[slug].idx}-${slug}`;

const tokens = {};
for (const line of fs.readFileSync(TOKENS_FILE, "utf8").trim().split("\n")) {
  const [slug, region, tok] = line.split("\t");
  if (slug && tok) tokens[slug] = { region, tok };
}

// readJSON returns parsed JSON for a captured payload, or null if absent.
function readJSON(slug, suffix) {
  const f = path.join(PAYLOADS, `${payloadPrefix(slug)}-${suffix}.json`);
  if (!fs.existsSync(f)) return null;
  return JSON.parse(fs.readFileSync(f, "utf8"));
}

// Derive the dynamic IDs the deep-link screenshots need from the committed
// payloads, so they always match the last seed rather than a frozen UUID.
function dynamicIDs(slug) {
  const risk = readJSON(slug, "request-risk");
  const campaigns = readJSON(slug, "campaigns");
  return {
    request: risk?.request?.id ?? null,
    campaign: campaigns?.campaigns?.[0]?.id ?? null,
  };
}

const browser = await chromium.launch();
let taken = 0;
let skipped = 0;

// shot opens a fresh context with the workspace token + locale primed before the
// SPA boots, navigates, optionally runs an interaction, and writes the PNG.
async function shot(slug, locale, route, name, { fullPage = true, action } = {}) {
  const t = tokens[slug];
  if (!t) { console.log(`  skip ${slug}/${name}: no token`); skipped++; return; }
  if (route === null) { console.log(`  skip ${slug}/${name}: missing dynamic id`); skipped++; return; }
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 1000 }, deviceScaleFactor: 2 });
  const page = await ctx.newPage();
  await page.addInitScript(([tok, l]) => {
    sessionStorage.setItem("sng.access_token", tok);
    localStorage.setItem("sng.locale", l);
  }, [t.tok, locale]);
  await page.goto(BASE + route, { waitUntil: "networkidle" });
  await page.waitForTimeout(1200);
  try { if (action) await action(page); } catch (e) { console.log(`  action failed for ${name}: ${e.message}`); }
  await page.waitForTimeout(600);
  const file = path.join(OUT, `${shotPrefix(slug)}-${name}.png`);
  await page.screenshot({ path: file, fullPage });
  console.log("  ->", file);
  taken++;
  await ctx.close();
}

const clickFrameworkTab = (label) => async (page) => {
  await page.getByRole("tab", { name: label, exact: true }).click();
  await page.waitForTimeout(800);
};

// The Live sessions screen defaults to "Active only"; the seeded recording is a
// closed session, so untick the filter to show it (and its replay affordance).
const showAllSessions = async (page) => {
  const box = page.getByRole("checkbox", { name: /active only/i });
  if (await box.isChecked()) await box.uncheck();
  await page.waitForTimeout(800);
};

// Open the first row of the recordings table to land on the replay player. The
// row id is dynamic (a fresh recording per seed), so we click rather than
// hard-code a URL — same reproducibility discipline as the rest of the harness.
const openFirstRecording = async (page) => {
  const row = page.getByRole("row").nth(1);
  await row.click();
  await page.waitForURL("**/pam/recordings/*", { timeout: 15000 });
  await page.waitForTimeout(1200);
};

const ids = Object.fromEntries(Object.keys(WS).map((s) => [s, dynamicIDs(s)]));

// ---- S1 Singapore (en) — flagship full surface ----
await shot("sg-acme-payments", "en", "/", "dashboard");
await shot("sg-acme-payments", "zh-Hans", "/", "dashboard-zh-Hans");
await shot("sg-acme-payments", "en", "/policies", "policies");
await shot("sg-acme-payments", "en", "/packs", "packs");
await shot("sg-acme-payments", "en", "/requests", "access-requests");
await shot("sg-acme-payments", "en", ids["sg-acme-payments"].request ? `/requests/${ids["sg-acme-payments"].request}` : null, "request-risk");
await shot("sg-acme-payments", "en", "/connectors", "connectors");
await shot("sg-acme-payments", "en", "/directory", "directory");
await shot("sg-acme-payments", "en", "/workflows", "workflows");
await shot("sg-acme-payments", "en", "/pam/targets", "pam-targets");
await shot("sg-acme-payments", "en", "/pam/leases", "pam-leases");
await shot("sg-acme-payments", "en", "/pam/sessions", "pam-sessions", { action: showAllSessions });
await shot("sg-acme-payments", "en", "/compliance/evidence", "compliance-pci-dss", { action: clickFrameworkTab("PCI-DSS") });
await shot("sg-acme-payments", "en", "/compliance/evidence", "compliance-soc2", { action: clickFrameworkTab("SOC 2") });
await shot("sg-acme-payments", "en", "/settings/roles", "roles-permissions");

// ---- S1 Singapore (en) — privileged-access depth (the flagship feature set) ----
// The outbound connector agent (zero inbound exposure), clientless browser
// access (web SSH + DB console), automatic + dynamic credential rotation, and
// the searchable session-recording store + in-browser replay player.
await shot("sg-acme-payments", "en", "/pam/agents", "pam-agents");
await shot("sg-acme-payments", "en", "/pam/web-access", "pam-web-access");
await shot("sg-acme-payments", "en", "/pam/rotation", "pam-rotation");
await shot("sg-acme-payments", "en", "/pam/recordings", "recordings-search");
await shot("sg-acme-payments", "en", "/pam/recordings", "recordings-replay", { action: openFirstRecording });
// Asset/account discovery + auto-onboarding: the inventory the connector agent's
// self-reported reach produces, reconciled into managed vs unmanaged candidates.
await shot("sg-acme-payments", "en", "/discovery", "discovery");

// ---- S2 US healthcare (en) — JML + certification ----
await shot("us-globex-health", "en", "/", "dashboard");
await shot("us-globex-health", "en", "/requests", "access-requests");
await shot("us-globex-health", "en", "/jml-runs", "jml-runs");
await shot("us-globex-health", "en", "/directory", "directory");
await shot("us-globex-health", "en", "/compliance/campaigns", "certification-campaigns");
await shot("us-globex-health", "en", ids["us-globex-health"].campaign ? `/compliance/campaigns/${ids["us-globex-health"].campaign}` : null, "certification-detail");
await shot("us-globex-health", "en", "/compliance/evidence", "compliance-evidence");
await shot("us-globex-health", "en", "/compliance/evidence", "compliance-soc2", { action: clickFrameworkTab("SOC 2") });

// ---- S3 Germany (de) ----
await shot("de-initech-retail", "de", "/", "dashboard");
await shot("de-initech-retail", "de", "/policies", "policies-de");
await shot("de-initech-retail", "de", "/compliance/evidence", "compliance-de");

// ---- S4 Vietnam (vi) ----
await shot("vn-umbrella-logistics", "vi", "/", "dashboard");
await shot("vn-umbrella-logistics", "vi", "/compliance/evidence", "compliance-vi");
await shot("vn-umbrella-logistics", "en", "/compliance/evidence", "compliance");

// ---- S5 UAE (ar, RTL) — PAM ----
await shot("ae-northwind-finance", "ar", "/", "dashboard-ar");
await shot("ae-northwind-finance", "en", "/", "dashboard");
await shot("ae-northwind-finance", "en", "/pam", "pam-overview");
await shot("ae-northwind-finance", "en", "/pam/targets", "pam-targets");
await shot("ae-northwind-finance", "en", "/pam/leases", "pam-leases");

// ---- S6 Australia (en) — certification + export ----
await shot("au-contoso-saas", "en", "/", "dashboard");
await shot("au-contoso-saas", "en", "/compliance/campaigns", "certification-campaigns");
await shot("au-contoso-saas", "en", "/compliance/evidence", "compliance-export", { action: clickFrameworkTab("SOC 2") });

// ---- S5 UAE — PAM register modal (protocol picker) ----
await shot("ae-northwind-finance", "en", "/pam/targets", "pam-register-protocols", {
  action: async (page) => {
    await page.getByRole("button", { name: "Register target" }).first().click();
    await page.waitForTimeout(700);
  },
});

// ---- S1 Singapore — policy SoD conflict + step-up MFA (interactive) ----
// Builds a throwaway draft that collides with the seeded default-deny policy,
// simulates it (grant-vs-deny conflict), then promotes to surface the step-up
// MFA gate. The draft is archived afterwards and the MFA is never completed, so
// the run leaves no live state behind.
await captureSodFlow();

await browser.close();
console.log(`DONE — ${taken} screenshots written, ${skipped} skipped`);

async function captureSodFlow() {
  const t = tokens["sg-acme-payments"];
  if (!t) { console.log("  skip SoD flow: no sg token"); skipped++; return; }
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 1000 }, deviceScaleFactor: 2 });
  const page = await ctx.newPage();
  await page.addInitScript((tok) => {
    sessionStorage.setItem("sng.access_token", tok);
    localStorage.setItem("sng.locale", "en");
  }, t.tok);
  try {
    await page.goto(BASE + "/policies/new", { waitUntil: "networkidle" });
    await page.waitForTimeout(1000);
    await page.getByPlaceholder("e.g. Engineering → production apps").fill("Grant all-staff to customer data (SoD test)");
    await page.getByRole("radio", { name: "Grant", exact: true }).click();
    const subjects = page.locator('label.field:has(span:text-is("Who / which groups")) input');
    await subjects.fill("group:all-staff");
    await subjects.press("Enter");
    const resources = page.locator('label.field:has(span:text-is("Which systems / resources")) input');
    await resources.fill("db:customer");
    await resources.press("Enter");
    await page.waitForTimeout(300);
    await page.getByRole("button", { name: "Create draft" }).click();
    await page.waitForURL("**/policies/*", { timeout: 15000 });
    await page.waitForTimeout(1200);

    await page.getByRole("button", { name: "Simulate", exact: true }).click();
    await page.waitForTimeout(1500);
    await page.screenshot({ path: path.join(OUT, "s1-sg-policy-simulate-conflict.png"), fullPage: true });
    console.log("  -> s1-sg-policy-simulate-conflict.png");
    taken++;

    await page.getByRole("button", { name: "Promote to live" }).click();
    await page.waitForTimeout(1200);
    const reason = page.getByPlaceholder(/Break-glass access approved/);
    if (await reason.count()) {
      await reason.fill("Break-glass: SoD test promotion for the blog evidence run.");
      await page.getByRole("button", { name: "Override and promote" }).click();
      await page.waitForTimeout(1500);
    }
    await page.screenshot({ path: path.join(OUT, "s1-sg-stepup-mfa.png"), fullPage: true });
    console.log("  -> s1-sg-stepup-mfa.png");
    taken++;

    // Back out: cancel the MFA modal and archive the throwaway draft.
    const cancel = page.getByRole("button", { name: "Cancel" });
    if (await cancel.count()) await cancel.first().click();
    await page.waitForTimeout(500);
    const archive = page.getByRole("button", { name: "Archive" });
    if (await archive.count()) { await archive.first().click(); await page.waitForTimeout(1000); }
  } catch (e) {
    console.log(`  SoD flow failed: ${e.message}`);
  } finally {
    await ctx.close();
  }
}
