# whatever2sbom — Python development tasks.
#
# Targets are POSIX make + GNU make compatible. Designed to mirror the
# same `bench-e2e` workflow as the Go port (branch: go-port) so the two
# implementations can be compared head-to-head with `hyperfine` on the
# same machine.

PYTHON       := python3
VENV         := .venv
VENV_BIN     := $(VENV)/bin
VENV_PYTHON  := $(VENV_BIN)/python
WHATEVER2SBOM := $(VENV_BIN)/whatever2sbom

.PHONY: help
help: ## Show this help (default target)
	@echo "whatever2sbom — make targets:"
	@awk 'BEGIN { FS = ":.*## " } /^[a-zA-Z_-]+:.*## / { printf "  %-14s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# Create a venv and install the package + test extras into it.
# Re-runs the install if the source changed (pyproject.toml is a stand-in
# for "anything important enough to reinstall for").
$(WHATEVER2SBOM): pyproject.toml
	$(PYTHON) -m venv $(VENV) || $(PYTHON) -m venv --copies $(VENV)
	$(VENV_PYTHON) -m pip install --upgrade pip
	$(VENV_PYTHON) -m pip install -e ".[dev]"
	@touch $(WHATEVER2SBOM)

.PHONY: venv
venv: $(WHATEVER2SBOM) ## Create venv + install package in editable mode

.PHONY: test
test: $(WHATEVER2SBOM) ## Run pytest
	$(VENV_BIN)/pytest tests/

.PHONY: bench-e2e
bench-e2e: $(WHATEVER2SBOM) ## End-to-end benchmark via hyperfine (mirrors the Go-port version)
	@command -v hyperfine >/dev/null || { \
		echo "hyperfine not found."; \
		echo "  Ubuntu 24.04+ / Debian 12+: sudo apt install hyperfine"; \
		echo "  Older systems:              cargo install hyperfine"; \
		exit 1; \
	}
	hyperfine --warmup 1 --runs 5 \
		'$(WHATEVER2SBOM) --product-supplier bench --no-licenses --no-apt-cache -o /tmp/bench-py-min.cdx.json' \
		'$(WHATEVER2SBOM) --product-supplier bench --no-licenses -o /tmp/bench-py-no-lic.cdx.json' \
		'$(WHATEVER2SBOM) --product-supplier bench -o /tmp/bench-py-full.cdx.json'

.PHONY: wheel
wheel: $(WHATEVER2SBOM) ## Build a distributable wheel into dist/
	rm -rf dist/
	$(VENV_PYTHON) -m build --wheel
	@echo ""
	@echo "Wheel ready: $$(ls dist/*.whl)"
	@echo ""
	@echo "Install locally:           pip install $$(ls dist/*.whl)"
	@echo "Transfer + install remote: scp $$(ls dist/*.whl) user@host:/tmp/ && ssh user@host pip install /tmp/$$(ls dist/*.whl | xargs basename)"

.PHONY: docs-venv
docs-venv: ## Create venv + install docs dependencies
	$(PYTHON) -m venv $(VENV) || $(PYTHON) -m venv --copies $(VENV)
	$(VENV_PYTHON) -m pip install --upgrade pip
	$(VENV_PYTHON) -m pip install -e ".[docs]"

.PHONY: docs-serve
docs-serve: docs-venv ## Serve the docs site locally with live reload
	$(VENV_BIN)/mkdocs serve

.PHONY: docs-build
docs-build: docs-venv ## Build the docs site into site/
	$(VENV_BIN)/mkdocs build --strict

.PHONY: clean
clean: ## Remove the venv, build artefacts, and generated SBOMs
	rm -rf $(VENV) build dist site *.egg-info src/*.egg-info
	rm -f sbom_*.cdx.json /tmp/bench-py-*.cdx.json
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type d -name .pytest_cache -prune -exec rm -rf {} +
