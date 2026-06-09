#!/usr/bin/env bash
#
# security-audit.sh — unified dependency vulnerability audit + single SBOM for
# the whole fishbone-access tree. It runs one scanner per ecosystem present in
# the repo and emits ONE consolidated CycloneDX SBOM:
#
#   • Go      — govulncheck (reachability-aware; only reports vulns the code path
#               can actually hit)
#   • npm     — npm audit over ui/ (the embedded Access console)
#   • Python  — pip-audit over every requirements*.txt (the access-ai-agent svc)
#   • Rust    — cargo audit over every crate (skipped cleanly while the tree has
#               no Cargo.toml; picked up automatically once a crate lands)
#   • SBOM    — syft scans the repo and writes a single CycloneDX file covering
#               all ecosystems at once
#
# "No ops": tools that are not already on PATH are fetched on demand and pinned —
# pip-audit/cargo-audit via their own toolchains, syft via its versioned
# installer into ./.tooling/bin — so a fresh checkout (dev laptop or CI) can run
# `make audit` with nothing pre-installed beyond go/node/python/cargo + uv.
#
# Exit status: non-zero if ANY scanner reports a vulnerability or errors, so the
# target is a real CI gate. Every scanner still runs (failures are accumulated,
# not short-circuited) and the SBOM is always written, so one run surfaces the
# full picture. Set SECURITY_AUDIT_REPORT_ONLY=1 to always exit 0 (report-only).
set -uo pipefail

# ---- configuration (all overridable from the environment) -------------------
SYFT_VERSION="${SYFT_VERSION:-v1.18.1}"
# The syft installer is fetched from an IMMUTABLE commit pin, never a moving
# branch: SYFT_INSTALLER_REF is the commit the SYFT_VERSION tag points to, and
# the download is integrity-checked against SYFT_INSTALLER_SHA256 before it is
# ever executed. This closes the supply-chain hole of piping a mutable
# `…/main/install.sh` straight into a shell — a compromised upstream branch (or
# a moved tag) cannot inject code here because both the ref and the bytes are
# pinned. Bump all three together when upgrading syft (the SHA256 is printed by
# `sha256sum` of the installer at that ref).
SYFT_INSTALLER_REF="${SYFT_INSTALLER_REF:-5e16e5031a13f8a11057feb8544decebfc43b4ed}"
SYFT_INSTALLER_SHA256="${SYFT_INSTALLER_SHA256:-709ae9171e3d44e456a111943c341d0bf0fd2176b41af124d019823a70c34a3f}"
GOVULNCHECK_VERSION="${GOVULNCHECK_VERSION:-latest}"
PIP_AUDIT_VERSION="${PIP_AUDIT_VERSION:-2.7.3}"
NPM_AUDIT_LEVEL="${NPM_AUDIT_LEVEL:-high}"
SBOM_OUT="${SBOM_OUT:-dist/sbom.cyclonedx.json}"
REPORT_ONLY="${SECURITY_AUDIT_REPORT_ONLY:-0}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
TOOLBIN="$REPO_ROOT/.tooling/bin"
mkdir -p "$TOOLBIN" "$(dirname "$SBOM_OUT")"
export PATH="$TOOLBIN:$PATH"

fail=0
section() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
note() { printf '   %s\n' "$1"; }

# ---- Go: govulncheck --------------------------------------------------------
section "govulncheck (Go modules)"
if command -v govulncheck >/dev/null 2>&1; then
	govulncheck ./... || fail=1
else
	note "govulncheck not on PATH; running via 'go run' (pinned ${GOVULNCHECK_VERSION})"
	go run "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}" ./... || fail=1
fi

# ---- npm: npm audit (ui/) ---------------------------------------------------
section "npm audit (ui/, level=${NPM_AUDIT_LEVEL}, runtime deps)"
if [ -f ui/package-lock.json ]; then
	# --omit=dev: the shipped artifact is the built SPA, so gate on runtime deps
	# (dev toolchain advisories do not reach tenants). npm audit reads the
	# lockfile and queries the registry; no install required.
	( cd ui && npm audit --omit=dev "--audit-level=${NPM_AUDIT_LEVEL}" ) || fail=1
else
	note "no ui/package-lock.json; skipping"
fi

# ---- Python: pip-audit ------------------------------------------------------
section "pip-audit (Python requirements)"
pyreqs="$(git ls-files '*requirements*.txt' 2>/dev/null || true)"
if [ -n "$pyreqs" ]; then
	if ! command -v uvx >/dev/null 2>&1; then
		note "uvx (uv) not found; cannot run pip-audit — install uv (https://docs.astral.sh/uv/)"
		fail=1
	else
		while IFS= read -r req; do
			[ -z "$req" ] && continue
			note "auditing $req"
			uvx --from "pip-audit==${PIP_AUDIT_VERSION}" pip-audit -r "$req" || fail=1
		done <<<"$pyreqs"
	fi
else
	note "no requirements*.txt; skipping"
fi

# ---- Rust: cargo audit ------------------------------------------------------
section "cargo audit (Rust crates)"
cargotomls="$(git ls-files '*Cargo.toml' 2>/dev/null || true)"
if [ -n "$cargotomls" ]; then
	if ! command -v cargo-audit >/dev/null 2>&1; then
		if command -v cargo >/dev/null 2>&1; then
			note "installing cargo-audit (cargo install --locked)"
			cargo install cargo-audit --locked >/dev/null 2>&1 || { note "cargo-audit install failed"; fail=1; }
		else
			note "cargo not found; cannot audit Rust crates"
			fail=1
		fi
	fi
	if command -v cargo-audit >/dev/null 2>&1; then
		while IFS= read -r ct; do
			[ -z "$ct" ] && continue
			note "auditing $(dirname "$ct")"
			( cd "$(dirname "$ct")" && cargo audit ) || fail=1
		done <<<"$cargotomls"
	fi
else
	note "no Cargo.toml in tree; skipping (no Rust crates yet)"
fi

# ---- single consolidated SBOM (syft) ----------------------------------------
section "SBOM → ${SBOM_OUT} (CycloneDX, all ecosystems)"
if ! command -v syft >/dev/null 2>&1; then
	note "bootstrapping syft ${SYFT_VERSION} into ${TOOLBIN} (installer pinned @ ${SYFT_INSTALLER_REF})"
	installer="$(mktemp)"
	# Fetch from the pinned commit, verify the bytes, THEN run — never pipe an
	# unverified remote script into a shell.
	if curl -sSfL "https://raw.githubusercontent.com/anchore/syft/${SYFT_INSTALLER_REF}/install.sh" -o "$installer"; then
		got="$(sha256sum "$installer" | awk '{print $1}')"
		if [ "$got" = "$SYFT_INSTALLER_SHA256" ]; then
			sh "$installer" -b "$TOOLBIN" "$SYFT_VERSION" >/dev/null 2>&1 ||
				{ note "syft install failed"; fail=1; }
		else
			note "syft installer checksum mismatch (want ${SYFT_INSTALLER_SHA256}, got ${got}); refusing to execute"
			fail=1
		fi
	else
		note "syft installer download failed (network?)"
		fail=1
	fi
	rm -f "$installer"
fi
if command -v syft >/dev/null 2>&1; then
	syft scan dir:. \
		--exclude './.tooling/**' \
		--exclude './ui/node_modules/**' \
		--exclude './dist/**' \
		-o "cyclonedx-json=${SBOM_OUT}" -q || fail=1
	if [ -f "$SBOM_OUT" ]; then
		note "wrote $SBOM_OUT ($(wc -c <"$SBOM_OUT") bytes)"
	fi
fi

# ---- result -----------------------------------------------------------------
if [ "$REPORT_ONLY" = "1" ]; then
	if [ "$fail" -ne 0 ]; then
		note "vulnerabilities or errors found (SECURITY_AUDIT_REPORT_ONLY=1 → exiting 0)"
	fi
	exit 0
fi
if [ "$fail" -ne 0 ]; then
	printf '\n\033[31maudit: vulnerabilities or scanner errors found\033[0m\n'
fi
exit "$fail"
