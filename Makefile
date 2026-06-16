# ShieldNet Access (fishbone-access) — developer + CI entrypoints.
# Run `make help` for the target list.

GO            ?= go
GOLANGCI      ?= golangci-lint
PKG           ?= ./...
TEST_TIMEOUT  ?= 180s

.DEFAULT_GOAL := help

# Blog evidence pipeline (blog/harness/*). The harnesses drive the REAL API so
# every artifact is a verbatim capture; see blog/posts/README.md for the env
# vars they require (AUTH_JWT_SECRET, ACCESS_CREDENTIAL_DEK, ACCESS_DATABASE_URL).
BLOG_API_BASE ?= http://localhost:8080
BLOG_ARTIFACTS ?= blog/artifacts
BLOG_UI_BASE  ?= http://localhost:5173

.PHONY: build vet test test-short test-integration tidy-check migrate-check lint-go lint ci \
        audit audit-report docker-up docker-down docker-logs help \
        blog-seed blog-capture blog-bench blog-screenshots blog-test blog-all

build: ## go build ./...
	$(GO) build $(PKG)

vet: ## go vet ./...
	$(GO) vet $(PKG)

test: ## go test -race -timeout=$(TEST_TIMEOUT) ./...
	$(GO) test -race -timeout=$(TEST_TIMEOUT) $(PKG)

test-short: ## go test -race -short ./...
	$(GO) test -race -timeout=60s -short $(PKG)

test-integration: ## integration-tagged suite (serialized)
	$(GO) test -race -timeout=300s -tags=integration -p 1 $(PKG)

tidy-check: ## fail if go.mod/go.sum are not tidy
	$(GO) mod tidy
	git diff --exit-code -- go.mod go.sum

migrate-check: ## validate SQL migrations (version integrity + lock-safety)
	$(GO) run ./cmd/migrate-lint

lint-go: migrate-check ## golangci-lint over the full tree (+ migrate-check)
	$(GOLANGCI) run

lint: vet lint-go ## run all lint gates

ci: vet test lint-go ## full CI gate locally

audit: ## dependency vuln scan (go+npm+pip+cargo) + single CycloneDX SBOM
	./scripts/security-audit.sh

audit-report: ## like 'audit' but never fails the build (report-only)
	SECURITY_AUDIT_REPORT_ONLY=1 ./scripts/security-audit.sh

docker-up: ## docker compose up --build --wait
	docker compose up --build --wait

docker-down: ## docker compose down -v
	docker compose down -v

docker-logs: ## tail compose logs
	docker compose logs --no-color --tail=200

blog-seed: ## seed 6 workspaces with the full lifecycle (idempotent; writes seed-summary.json)
	$(GO) run ./blog/harness/seed -base $(BLOG_API_BASE) -out $(BLOG_ARTIFACTS)

blog-capture: ## capture verbatim API payloads + step-up-gated evidence-pack exports
	$(GO) run ./blog/harness/freshenagents
	$(GO) run ./blog/harness/capture -base $(BLOG_API_BASE) -out $(BLOG_ARTIFACTS)/payloads -summary $(BLOG_ARTIFACTS)/seed-summary.json

blog-test: ## run + tee the connector / compliance / handler test matrices
	$(GO) test ./internal/services/access/connectors/... -v 2>&1 | tee $(BLOG_ARTIFACTS)/connector-test-matrix.txt
	$(GO) test ./internal/services/compliance/... -v 2>&1 | tee $(BLOG_ARTIFACTS)/compliance-test-results.txt
	$(GO) test ./internal/handlers/... -v 2>&1 | tee $(BLOG_ARTIFACTS)/handler-test-results.txt

blog-bench: ## time the live API on this VM (latency/throughput; writes benchmark-results.json)
	$(GO) run ./blog/harness/bench -base $(BLOG_API_BASE) -out $(BLOG_ARTIFACTS)/benchmark-results.json

blog-screenshots: ## capture console screenshots (needs the UI dev server + seeded data; installs Playwright on first run)
	npm --prefix blog/harness/screenshots install --no-audit --no-fund
	npx --prefix blog/harness/screenshots playwright install chromium
	$(GO) run ./blog/harness/freshenagents
	TOK=$$(mktemp) && trap 'rm -f $$TOK' EXIT && \
	  $(GO) run ./blog/harness/minttokens > $$TOK && \
	  BLOG_UI_BASE=$(BLOG_UI_BASE) BLOG_TOKENS=$$TOK BLOG_PAYLOADS=$(BLOG_ARTIFACTS)/payloads \
	  BLOG_SHOTS_OUT=$(BLOG_ARTIFACTS)/screenshots node blog/harness/screenshots/shoot.mjs

blog-all: blog-seed blog-capture blog-bench blog-test ## seed, capture, benchmark, then run the test matrices

help: ## print this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
