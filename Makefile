# whatever2sbom — common development tasks.
#
# Targets are POSIX make + GNU make compatible. On Windows, either run
# the underlying go commands directly, or use a `make` from WSL, Git Bash,
# or GnuWin32.

BINARY  := whatever2sbom
PKG     := ./cmd/whatever2sbom
VERSION := $(shell git describe --tags --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.toolVersion=$(VERSION)

# Debian package version. Must be a strict semver (no leading "v", no "+").
# Override at the command line for releases:
#   make deb DEB_VERSION=0.2.0
DEB_VERSION ?= 0.1.0

# nfpm — Go-native multi-format packager (.deb / .rpm / .apk).
# Not in any apt repo, so we vendor a pinned version into ./bin/ via
# `go install` — uses the Go toolchain we already require, no curl/wget
# needed, works on every platform Go supports.
NFPM_VERSION := 2.41.0
NFPM_BIN     := ./bin/nfpm

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
bench-e2e: build ## End-to-end benchmark on a real dpkg system (needs hyperfine)
	@command -v hyperfine >/dev/null || { \
		echo "hyperfine not found."; \
		echo "  Ubuntu 24.04+ / Debian 12+: sudo apt install hyperfine"; \
		echo "  Older systems:              cargo install hyperfine"; \
		exit 1; \
	}
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

# ── .deb packaging ──────────────────────────────────────────────────────────
#
# Produces a single-arch .deb that installs the binary into /usr/bin.
# Works on every modern Debian-family release (Ubuntu 22.04, 24.04, 26.04,
# Debian 12+) — the binary is fully static and only depends on dpkg + apt,
# both always present on those systems.

.PHONY: deb
deb: build $(NFPM_BIN) ## Build a .deb for the host arch into ./dist/
	@mkdir -p dist
	@arch=$$(dpkg --print-architecture 2>/dev/null || echo amd64); \
	VERSION=$(DEB_VERSION) ARCH=$$arch $(NFPM_BIN) pkg \
		--packager deb \
		--target dist/$(BINARY)_$(DEB_VERSION)_$$arch.deb \
		-f nfpm.yaml
	@echo
	@ls -lh dist/$(BINARY)_$(DEB_VERSION)_*.deb
	@echo
	@echo "Install with:  sudo dpkg -i dist/$(BINARY)_$(DEB_VERSION)_*.deb"
	@echo "Uninstall:     sudo apt remove $(BINARY)"

.PHONY: deb-all
deb-all: $(NFPM_BIN) ## Cross-build .deb for amd64 + arm64
	@mkdir -p dist
	@for arch in amd64 arm64; do \
		echo ">> Building $$arch binary"; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG); \
		echo ">> Packaging $$arch .deb"; \
		VERSION=$(DEB_VERSION) ARCH=$$arch $(NFPM_BIN) pkg \
			--packager deb \
			--target dist/$(BINARY)_$(DEB_VERSION)_$$arch.deb \
			-f nfpm.yaml; \
	done
	@rm -f $(BINARY)
	@echo
	@ls -lh dist/$(BINARY)_$(DEB_VERSION)_*.deb

# Build nfpm via the Go toolchain into ./bin/ on first use.
# Compiles from source (~20 s) but needs only `go`, which we already have.
$(NFPM_BIN):
	@mkdir -p bin
	@echo "Installing nfpm v$(NFPM_VERSION) via go install (one-time, ~20s)"
	GOBIN=$(CURDIR)/bin go install github.com/goreleaser/nfpm/v2/cmd/nfpm@v$(NFPM_VERSION)
	@echo "nfpm ready at $(NFPM_BIN)"
