# ShieldNet Access (fishbone-access) — developer + CI entrypoints.
# Run `make help` for the target list.

GO            ?= go
GOLANGCI      ?= golangci-lint
PKG           ?= ./...
TEST_TIMEOUT  ?= 180s

.DEFAULT_GOAL := help

.PHONY: build vet test test-short test-integration tidy-check lint-go lint ci \
        docker-up docker-down docker-logs help

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

lint-go: ## golangci-lint over the full tree
	$(GOLANGCI) run

lint: vet lint-go ## run all lint gates

ci: vet test lint-go ## full CI gate locally

docker-up: ## docker compose up --build --wait
	docker compose up --build --wait

docker-down: ## docker compose down -v
	docker compose down -v

docker-logs: ## tail compose logs
	docker compose logs --no-color --tail=200

help: ## print this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
