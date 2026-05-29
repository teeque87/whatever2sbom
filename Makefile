# whatever2sbom — common development tasks.
#
# Targets are POSIX make + GNU make compatible. On Windows, either run
# the underlying go commands directly, or use a `make` from WSL, Git Bash,
# or GnuWin32.

BINARY  := whatever2sbom
PKG     := ./cmd/whatever2sbom
VERSION := $(shell git describe --tags --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.toolVersion=$(VERSION)

# Hyperfine for end-to-end benchmarking — auto-downloaded into ./bin so we
# never need sudo or a system package install. Bumped intentionally; pin a
# version so the download is reproducible.
HYPERFINE_VERSION := 1.18.0
HYPERFINE_BIN     := ./bin/hyperfine

UNAME_S := $(shell uname -s 2>/dev/null)
UNAME_M := $(shell uname -m 2>/dev/null)
ifeq ($(UNAME_S)/$(UNAME_M),Linux/x86_64)
    HYPERFINE_ASSET := hyperfine-v$(HYPERFINE_VERSION)-x86_64-unknown-linux-musl
else ifeq ($(UNAME_S)/$(UNAME_M),Linux/aarch64)
    HYPERFINE_ASSET := hyperfine-v$(HYPERFINE_VERSION)-aarch64-unknown-linux-gnu
else ifeq ($(UNAME_S)/$(UNAME_M),Darwin/x86_64)
    HYPERFINE_ASSET := hyperfine-v$(HYPERFINE_VERSION)-x86_64-apple-darwin
else ifeq ($(UNAME_S)/$(UNAME_M),Darwin/arm64)
    HYPERFINE_ASSET := hyperfine-v$(HYPERFINE_VERSION)-aarch64-apple-darwin
endif

.PHONY: help
help: ## Show this help (default target)
	@echo "whatever2sbom — make targets:"
	@awk 'BEGIN { FS = ":.*## " } /^[a-zA-Z_-]+:.*## / { printf "  %-14s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: build
build: ## Build a stripped, static binary into ./$(BINARY)
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

.PHONY: install
install: ## Install the binary into $$GOBIN (or $$GOPATH/bin)
	CGO_ENABLED=0 go install -ldflags "$(LDFLAGS)" $(PKG)

.PHONY: test
test: ## Run all unit tests
	go test ./...

.PHONY: cover
cover: ## Run tests with HTML coverage report
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

.PHONY: bench
bench: ## Run Go micro-benchmarks for hot paths (any OS)
	go test -bench=. -benchmem -run=^$$ ./...

.PHONY: bench-e2e
bench-e2e: build $(HYPERFINE_BIN) ## End-to-end benchmark on a real dpkg system (auto-downloads hyperfine)
	$(HYPERFINE_BIN) --warmup 1 --runs 5 \
		'./$(BINARY) --product-supplier bench --no-licenses --no-apt-cache -o /tmp/bench-min.cdx.json' \
		'./$(BINARY) --product-supplier bench --no-licenses -o /tmp/bench-no-lic.cdx.json' \
		'./$(BINARY) --product-supplier bench -o /tmp/bench-full.cdx.json'

# Auto-download hyperfine into ./bin/ on first use. Skips if already present.
$(HYPERFINE_BIN):
	@if [ -z "$(HYPERFINE_ASSET)" ]; then \
		echo "unsupported platform $(UNAME_S)/$(UNAME_M); install hyperfine manually and re-run"; \
		exit 1; \
	fi
	@mkdir -p bin
	@echo "Downloading hyperfine v$(HYPERFINE_VERSION) ($(HYPERFINE_ASSET))"
	@curl -fsSL -o /tmp/hyperfine.tar.gz \
		https://github.com/sharkdp/hyperfine/releases/download/v$(HYPERFINE_VERSION)/$(HYPERFINE_ASSET).tar.gz
	@tar -xzf /tmp/hyperfine.tar.gz -C bin --strip-components=1 $(HYPERFINE_ASSET)/hyperfine
	@rm -f /tmp/hyperfine.tar.gz
	@chmod +x $(HYPERFINE_BIN)
	@echo "hyperfine ready at $(HYPERFINE_BIN)"

.PHONY: lint
lint: ## go vet + gofmt check
	go vet ./...
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt: the following files need formatting:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

.PHONY: fmt
fmt: ## Apply gofmt to all Go files
	gofmt -w .

.PHONY: tidy
tidy: ## Tidy go.mod / go.sum
	go mod tidy

.PHONY: clean
clean: ## Remove build artifacts, downloaded tools, and generated SBOMs
	rm -f $(BINARY) $(BINARY).exe coverage.out
	rm -f sbom_*.cdx.json /tmp/bench-*.cdx.json
	rm -rf bin dist

# ── cross-compilation matrix ────────────────────────────────────────────────

.PHONY: release
release: ## Build stripped binaries for linux/{amd64,arm64} into ./dist/
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64 $(PKG)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64 $(PKG)
