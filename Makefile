# whatever2sbom — common development tasks.
#
# Targets are POSIX make + GNU make compatible. On Windows, either run
# the underlying go commands directly, or use a `make` from WSL, Git Bash,
# or GnuWin32.

BINARY  := whatever2sbom
PKG     := ./cmd/whatever2sbom
VERSION := $(shell git describe --tags --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.toolVersion=$(VERSION)

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
bench-e2e: build ## End-to-end benchmark on a real dpkg system (Linux only; needs hyperfine)
	@command -v hyperfine >/dev/null || { echo "install hyperfine first: cargo install hyperfine"; exit 1; }
	hyperfine --warmup 1 --runs 5 \
		'./$(BINARY) --product-supplier bench --no-licenses --no-apt-cache -o /tmp/bench-min.cdx.json' \
		'./$(BINARY) --product-supplier bench --no-licenses -o /tmp/bench-no-lic.cdx.json' \
		'./$(BINARY) --product-supplier bench -o /tmp/bench-full.cdx.json'

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
clean: ## Remove build artifacts and generated SBOMs
	rm -f $(BINARY) $(BINARY).exe coverage.out
	rm -f sbom_*.cdx.json /tmp/bench-*.cdx.json

# ── cross-compilation matrix ────────────────────────────────────────────────

.PHONY: release
release: ## Build stripped binaries for linux/{amd64,arm64} into ./dist/
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64 $(PKG)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64 $(PKG)
