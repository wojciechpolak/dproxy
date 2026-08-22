# dproxy developer tasks.
#
# Every check here also runs in CI, and CI treats each as blocking.
#
# The product module has no dependencies at all: "go.mod" lists none and there
# is no "go.sum". Development tools live in their own module under tools/ and
# are built into bin/, so nothing a linter needs can appear in the dependency
# graph of the thing that ships.

GO ?= go
BIN := bin
TOOLS := tools
COVERAGE_MIN ?= 90.0

.DEFAULT_GOAL := help

.PHONY: help
help: ## List the available targets
	@grep -E '^[a-zA-Z0-9_/.-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Tool binaries. Each is built from the tools module, which is separate from
# the product module, so "go build ./..." never sees these dependencies.
$(BIN)/goimports: $(TOOLS)/go.mod $(TOOLS)/go.sum
	$(GO) -C $(TOOLS) build -o ../$(BIN)/goimports golang.org/x/tools/cmd/goimports

$(BIN)/deadcode: $(TOOLS)/go.mod $(TOOLS)/go.sum
	$(GO) -C $(TOOLS) build -o ../$(BIN)/deadcode golang.org/x/tools/cmd/deadcode

$(BIN)/markdownfmt: $(TOOLS)/go.mod $(TOOLS)/go.sum
	$(GO) -C $(TOOLS) build -o ../$(BIN)/markdownfmt github.com/Kunde21/markdownfmt/v3/cmd/markdownfmt

$(BIN)/staticcheck: $(TOOLS)/go.mod $(TOOLS)/go.sum
	$(GO) -C $(TOOLS) build -o ../$(BIN)/staticcheck honnef.co/go/tools/cmd/staticcheck

$(BIN)/govulncheck: $(TOOLS)/go.mod $(TOOLS)/go.sum
	$(GO) -C $(TOOLS) build -o ../$(BIN)/govulncheck golang.org/x/vuln/cmd/govulncheck

# mdwrap is this repository's own tool: markdownfmt has no width option, so
# mdwrap makes the line breaks and markdownfmt -soft-wraps keeps them.
$(BIN)/mdwrap: $(TOOLS)/go.mod $(TOOLS)/mdwrap/main.go
	$(GO) -C $(TOOLS) build -o ../$(BIN)/mdwrap ./mdwrap

.PHONY: tools
tools: $(BIN)/goimports $(BIN)/deadcode $(BIN)/markdownfmt $(BIN)/staticcheck $(BIN)/govulncheck $(BIN)/mdwrap ## Build the development tools

.PHONY: build
build: ## Compile every package and write bin/dproxy
	$(GO) build ./...
	mkdir -p $(BIN)
	$(GO) build -trimpath -o $(BIN)/dproxy ./cmd/dproxy

.PHONY: release
release: ## Build reproducible release files (set TAG=v1.2.3)
	@test -n "$(TAG)" || { echo "TAG is required, for example TAG=v1.2.3" >&2; exit 2; }
	./scripts/build-release.sh "$(TAG)" dist

.PHONY: bump
bump: ## Bump VERSION (set VERSION=major, minor, patch, or x.y.z)
	@test -n "$(VERSION)" || { echo "VERSION is required, for example VERSION=patch" >&2; exit 2; }
	$(GO) -C $(TOOLS) run ./versionbump -root .. "$(VERSION)"

.PHONY: release-check
release-check: ## Rebuild a release target twice and compare every byte
	./scripts/check-release.sh

.PHONY: docker-build
docker-build: ## Build the non-root remote-server container image
	docker build --tag dproxy:local .

.PHONY: docker-build-amd64
docker-build-amd64: ## Build the remote-server image for a Linux amd64 NAS
	docker build --platform linux/amd64 --tag dproxy:local .

.PHONY: fmt
fmt: $(BIN)/goimports ## Format Go source with gofmt and goimports
	$(GO) fmt ./...
	$(BIN)/goimports -w .

.PHONY: fmt-check
fmt-check: $(BIN)/goimports ## Fail if any Go source is unformatted
	./scripts/check-format.sh $(BIN)/goimports

.PHONY: md-fmt
md-fmt: $(BIN)/markdownfmt ## Format every Markdown file with markdownfmt
	find . -name '*.md' -not -path './.git/*' -exec $(BIN)/markdownfmt -soft-wraps -w {} +

.PHONY: md-wrap
md-wrap: $(BIN)/mdwrap ## Re-wrap Markdown prose at 80 columns, then format
	find . -name '*.md' -not -path './.git/*' -exec $(BIN)/mdwrap -w {} +
	$(MAKE) md-fmt

.PHONY: md-check
md-check: $(BIN)/markdownfmt $(BIN)/mdwrap ## Fail if Markdown is unformatted or wrapped past 80 columns
	./scripts/check-markdown.sh $(BIN)/markdownfmt $(BIN)/mdwrap

.PHONY: vet
vet: ## Run go vet
	$(GO) vet ./...

.PHONY: staticcheck
staticcheck: $(BIN)/staticcheck ## Run staticcheck
	$(BIN)/staticcheck ./...

.PHONY: deadcode
deadcode: $(BIN)/deadcode ## Report unreachable functions from the dproxy command and its tests
	$(BIN)/deadcode -test ./cmd/dproxy

.PHONY: test
test: ## Run the unit tests
	$(GO) test ./...

.PHONY: coverage
coverage: ## Run unit tests and enforce the aggregate coverage floor
	GO="$(GO)" ./scripts/check-coverage.sh "$(COVERAGE_MIN)"

.PHONY: test-tools
test-tools: ## Run the tests of this repository's own tools
	$(GO) -C $(TOOLS) test ./...

.PHONY: race
race: ## Run the tests under the race detector
	$(GO) test -race ./...

.PHONY: vuln
vuln: $(BIN)/govulncheck ## Check the product module for known vulnerabilities
	$(BIN)/govulncheck ./...

.PHONY: vuln-tools
vuln-tools: tools ## Check the built development tools for known vulnerabilities
	@for tool in $(BIN)/goimports $(BIN)/deadcode $(BIN)/markdownfmt $(BIN)/staticcheck $(BIN)/govulncheck; do \
		echo "==> $$tool"; \
		$(BIN)/govulncheck -mode=binary "$$tool" || exit 1; \
	done

.PHONY: deps-check
deps-check: ## Fail if the product module gained a dependency
	./scripts/check-deps.sh

.PHONY: tidy-check
tidy-check: ## Fail if either module's go.mod or go.sum would change
	./scripts/check-tidy.sh

.PHONY: e2e-local
e2e-local: ## Run the in-process end-to-end topology
	$(GO) test -race -tags e2e ./...

.PHONY: e2e-docker
e2e-docker: ## Run the end-to-end suite against the production remote image
	./scripts/docker-e2e.sh

.PHONY: e2e
e2e: e2e-local e2e-docker ## Run every deterministic end-to-end test

.PHONY: e2e-cloudflare
e2e-cloudflare: ## Run the real Cloudflare relay and packet-capture privacy test
	./scripts/cloudflare-privacy-test.sh

.PHONY: provider-compat
provider-compat: ## Test Codex CLI, Claude Code, curl, git, streaming, and WebSockets locally
	DPROXY_PROVIDER_COMPAT=1 $(GO) test -race -tags e2e ./internal/integration \
		-run 'TestHTTPSProxyCompatibility|TestProviderCLICompatibility|TestProviderStyle'

.PHONY: clean
clean: ## Remove built binaries
	rm -rf $(BIN)

.PHONY: check
check: fmt-check md-check deps-check tidy-check vet staticcheck deadcode build test coverage test-tools race vuln release-check ## Run the full local gate

# ci is what the workflows run: the same gate plus the end-to-end suite.
.PHONY: ci
ci: check e2e ## Run everything CI runs
