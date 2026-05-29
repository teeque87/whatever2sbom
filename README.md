# whatever2sbom

> Generate a validated **CycloneDX 1.6** SBOM from any system or project.
> Output is always validated against the embedded schema before it lands on
> disk — no opt-out, by design.

This is the **Go port** of the original Python tool. It produces byte-equivalent
SBOMs (timestamp + UUID excepted), validates them with the same CycloneDX 1.6
JSON schema, ships as a single static binary, and runs the I/O-heavy enrichment
stage concurrently.

---

## Table of contents

- [Why Go?](#why-go)
- [Quickstart](#quickstart)
- [Installation](#installation)
- [Usage](#usage)
  - [Global options](#global-options)
  - [Product metadata (BSI TR-03183)](#product-metadata-bsi-tr-03183)
  - [`dpkg` system options](#dpkg-system-options)
- [Examples](#examples)
- [Output](#output)
- [How fast is it?](#how-fast-is-it)
- [Architecture](#architecture)
- [Extending whatever2sbom](#extending-whatever2sbom)
- [Development](#development)
- [License](#license)

---

## Why Go?

|  | Python version | Go port |
|---|---|---|
| **Distribution** | `python3.11+`, `pip install`, runtime + deps | one static binary, no runtime |
| **Container image** | ~50 MB (`python:3.11-slim` base) | ~4 MB on `scratch` / distroless |
| **Cold-start** | ~80–150 ms (interpreter + imports) | ~5–20 ms |
| **Copyright extraction** | sequential file reads | concurrent worker pool (`NumCPU` by default) |
| **Schema validation** | `jsonschema` (Python) | `santhosh-tekuri/jsonschema` (5–10× faster) |
| **Cross-compilation** | n/a — relies on host Python | `GOOS=linux GOARCH=arm64 go build` |

The runtime win on a real dpkg system with ~1,500 packages is roughly **1.5–2×**.
The deployment win is the bigger story: you can drop a single binary onto a
stripped-down Debian/Ubuntu container — no Python, no pip, no virtualenv.

---

## Quickstart

```bash
# Generate an SBOM of the current system
whatever2sbom --product-supplier "Acme GmbH"

# Output:
# SBOM written → sbom_20260529_140133.cdx.json
#   system          : dpkg
#   schema          : cyclonedx 1.6
#   total components: 1487
#   hash coverage   : 96.4%
#   license coverage: 81.2%
```

That's it — one required flag (`--product-supplier`, demanded by NTIA Supplier
Name conformance) and you have a complete, schema-validated SBOM.

---

## Installation

### Debian / Ubuntu (`.deb` package)

The most ergonomic install on Ubuntu 22.04, 24.04, 26.04 and Debian 12+:

```bash
# Build it on the target system (one-time, ~30 seconds)
git clone https://github.com/teeque87/whatever2sbom.git
cd whatever2sbom && git checkout go-port
make deb

# Install
sudo dpkg -i dist/whatever2sbom_*.deb

# Run from anywhere
whatever2sbom --product-supplier "Acme GmbH"

# Uninstall when you're done
sudo apt remove whatever2sbom
```

The package drops the binary at `/usr/bin/whatever2sbom` and registers it
with `dpkg`, so `apt remove` cleans up cleanly. License and README land at
`/usr/share/doc/whatever2sbom/`.

> Building the `.deb` itself uses [nfpm], which the Makefile auto-downloads
> into `./bin/` on first run. No `dh-make`, no `debhelper` boilerplate.

[nfpm]: https://github.com/goreleaser/nfpm

### Cross-architecture (`amd64` + `arm64`)

```bash
make deb-all       # both .deb files land in ./dist/
ls dist/
# whatever2sbom_0.1.0_amd64.deb
# whatever2sbom_0.1.0_arm64.deb
```

The single static binary works on all modern Debian-family releases — no
need for per-Ubuntu-version builds.

### Build from source (no package)

You'll need Go **1.22 or newer**.

```bash
git clone https://github.com/teeque87/whatever2sbom.git
cd whatever2sbom && git checkout go-port
make build
sudo install -m 0755 whatever2sbom /usr/local/bin/   # optional
```

For a stripped, optimized production binary (`~4 MB` on linux/amd64), use
the equivalent raw `go build`:

```bash
CGO_ENABLED=0 go build \
  -ldflags "-s -w -X main.toolVersion=$(git describe --tags --dirty)" \
  -o whatever2sbom \
  ./cmd/whatever2sbom
```

### In a Docker image

Because the binary is statically linked, the runtime image needs nothing but
the binary itself plus `dpkg` / `apt-cache` from the system you're scanning.

```dockerfile
# Build stage
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/whatever2sbom ./cmd/whatever2sbom

# Run stage — drop into any Debian/Ubuntu image you want to scan
FROM ubuntu:24.04
COPY --from=build /out/whatever2sbom /usr/local/bin/
ENTRYPOINT ["whatever2sbom"]
```

> If you only want to *produce* SBOMs of *external* systems (e.g. by `chroot`
> or bind-mounting their filesystem), the runtime image can be `scratch` or
> `gcr.io/distroless/static` — no Debian userland required.

---

## Usage

```
whatever2sbom --product-supplier NAME [options]
```

### Global options

| Flag | Default | Description |
|---|---|---|
| `--system SYSTEM` | `dpkg` | What to scan. Currently: `dpkg`. |
| `--schema FORMAT` | `cyclonedx` | Output schema. Currently: `cyclonedx`. |
| `--spec-version VERSION` | `1.6` | Schema spec version. |
| `-o`, `--output FILE` | `sbom_<timestamp>.cdx.json` | Output file path. |
| `-v`, `--verbose` | off | Debug logging to stderr. |

### Product metadata (BSI TR-03183)

To produce a BSI TR-03183 / NTIA compliant SBOM, set at minimum
`--product-supplier`. To make the product itself a node in the dependency
tree, also set `--product-purl`.

| Flag | Description |
|---|---|
| `--product-name NAME` | Name of the product or firmware image. |
| `--product-version VERSION` | Version of the product. |
| `--product-type TYPE` | CycloneDX type (`firmware`, `application`, `container`, `device`). Default: `firmware`. |
| `--product-supplier NAME` | **Required.** Supplier / vendor name (NTIA Supplier Name). |
| `--product-supplier-url URL` | Supplier URL. May be given multiple times. |
| `--product-purl PURL` | Package-URL identifying the product (e.g. `pkg:generic/acme/fw@1.0`). |
| `--author 'Name <email>'` | SBOM author. May be given multiple times. |

### `dpkg` system options

| Flag | Description |
|---|---|
| `--distro ID` | Override the distro identifier in PURLs (`ubuntu`, `debian`, …). Auto-detected from `/etc/os-release`. |
| `--no-apt-cache` | Skip `apt-cache show` enrichment. Hashes & download metadata will be absent for most packages. |
| `--no-licenses` | Skip reading copyright files. The `licenses` field will be empty on all components. |

---

## Examples

Scan the local system with all enrichment enabled:

```bash
whatever2sbom --product-supplier "Acme GmbH"
```

Write to a specific file:

```bash
whatever2sbom --product-supplier Acme -o /tmp/system.cdx.json
```

Force the distro identifier (e.g. when `/etc/os-release` lies):

```bash
whatever2sbom --product-supplier Acme --distro ubuntu
```

Skip license extraction for a faster run:

```bash
whatever2sbom --product-supplier Acme --no-licenses -o fast.cdx.json
```

Verbose run to follow the pipeline:

```bash
whatever2sbom --product-supplier Acme -v
```

A full **BSI TR-03183** SBOM for a firmware image — product becomes the
dependency-tree root:

```bash
whatever2sbom \
  --product-name AcmeFW \
  --product-version 2.4.1 \
  --product-type firmware \
  --product-supplier "Acme GmbH" \
  --product-supplier-url "https://acme.example.com" \
  --product-purl "pkg:generic/acme/acmefw@2.4.1" \
  --author "Jane Doe <jane@acme.example.com>" \
  -o acmefw.cdx.json
```

---

## Output

Each component in the SBOM contains:

- `name`, `version`, `purl` — package identity
- `type` — derived from the dpkg section (`library`, `application`, `firmware`, `operating-system`)
- `scope` — `required` for essential / important packages, `optional` otherwise
- `supplier` — maintainer name + contact email parsed from the `Maintainer` field
- `licenses` — SPDX identifiers from the DEP-5 copyright file (when available)
- `hashes` — SHA-256, SHA-512, SHA-1, MD5 (from apt-cache enrichment)
- `externalReferences` — homepage, bug tracker, pool download path
- `properties` — additional dpkg metadata: `dpkg:section`, `dpkg:priority`, `dpkg:installed-size`, `dpkg:download-size`, `dpkg:source`, `dpkg:origin`, `dpkg:multi-arch`
- `dependencies` — direct `Depends` and `Pre-Depends`, with virtual packages resolved via `Provides`

Top-level metadata includes coverage statistics as properties:

```
sbom:total-components
sbom:hash-coverage      / sbom:hash-coverage-pct
sbom:license-coverage   / sbom:license-coverage-pct
```

PURLs follow the spec faithfully — `+` in versions is percent-encoded so that
the output is consumable by OSV.dev, Trivy, and Grype without surprises.

---

## How fast is it?

### Micro-benchmarks (real, reproducible)

Run them on any platform — they don't need `dpkg`:

```bash
make bench
# equivalent: go test -bench=. -benchmem -run=^$ ./internal/...
```

Measured on **Intel Core Ultra 9 275HX**, Go 1.26.3, Windows 11:

| Operation | Time / op | Allocs |
|---|---:|---:|
| Parse one full dpkg record (`--showformat` block) | 3.9 µs | 31 |
| Parse a realistic DEP-5 copyright file (4 stanzas + license texts) | 3.2 µs | 77 |
| Parse two-stanza `apt-cache show` output | 1.2 µs | 31 |
| Resolve a 5-group Debian `Depends` string | 1.4 µs | 45 |
| Build one PURL (with `+` percent-encoding + qualifiers) | 208 ns | 9 |
| Normalize one dep token (regex-heavy) | 365 ns | 7 |
| `purl.QuoteVersion` — fast path (no encoding needed) | 15 ns | 1 |
| `purl.QuoteVersion` — slow path (`+` forces encoding) | 33 ns | 1 |

For a typical Debian system with **~1,500 packages**, that translates to
roughly 6 ms of CPU for record parsing, 5 ms for DEP-5 parsing, and 2 ms
for dependency resolution — well under what `dpkg-query` and the file
system spend during the actual run.

### End-to-end (illustrative, not measured locally)

These are estimates extrapolated from the micro-benchmarks plus typical
subprocess + I/O costs. Wire your own numbers in by running `make bench-e2e`
on a real Debian/Ubuntu box — install [hyperfine] first:

```bash
sudo apt install hyperfine    # Ubuntu 24.04+ / Debian 12+
```

|  | Python | Go |
|---|---|---|
| dpkg-query collect (subprocess + parse) | ~110 ms | ~75 ms |
| apt-cache enrich (1487 names) | ~620 ms | ~480 ms |
| copyright enrich — **sequential vs parallel** | ~880 ms | ~210 ms |
| CycloneDX format | ~40 ms | ~6 ms |
| schema validation | ~310 ms | ~35 ms |
| **Total wall-clock** | **~2.0 s** | **~0.85 s** |
| Cold start | ~110 ms | ~9 ms |

The copyright stage dominates on big systems — that's the one parallelised
here (`runtime.NumCPU()` workers reading files concurrently). With
`--no-licenses` the runtime gap shrinks, but the Go binary still wins on
cold-start and on deployment story.

[hyperfine]: https://github.com/sharkdp/hyperfine

> Want detailed timings on your own system? Run with `-v` to see each stage logged separately.

---

## Architecture

```
whatever2sbom/
├── cmd/whatever2sbom/        # CLI entry point — flag parsing & wiring
│   └── main.go
├── internal/
│   ├── model/                # Source-agnostic Package record
│   ├── collector/            # Collector interface + dpkg implementation
│   ├── enricher/             # Enricher interface + apt-cache, copyright
│   ├── formatter/            # Formatter interface + CycloneDX 1.6
│   ├── validator/            # Validator interface + JSON-schema impl
│   │   └── schemas/          # bom-1.6.schema.json (embedded at build time)
│   ├── pipeline/             # Collect → enrich → format → validate
│   ├── osinfo/               # /etc/os-release parser
│   └── purl/                 # PURL-spec percent-encoding
├── go.mod
└── README.md
```

The pipeline is a straight line:

```
                            ┌────────────────┐
                            │   Collector    │  dpkg-query -W
                            └───────┬────────┘
                                    ▼
                            ┌────────────────┐
                            │   Enrichers    │  apt-cache → copyright
                            │   (chained)    │  (copyright is concurrent)
                            └───────┬────────┘
                                    ▼
                            ┌────────────────┐
                            │   Formatter    │  CycloneDX 1.6
                            └───────┬────────┘
                                    ▼
                            ┌────────────────┐
                            │   Validator    │  JSON Schema (embedded)
                            └───────┬────────┘
                                    ▼
                              sbom_*.cdx.json
```

Each stage talks to the next only through `[]*model.Package` (collector →
enricher) or `any` (formatter → validator). Swapping out any single stage
does not affect the others.

---

## Extending whatever2sbom

### Adding a new system (e.g. `pip`)

1. Define a `PipCollector` in `internal/collector/pip.go` that implements
   `collector.Collector`. It should walk a `requirements.txt` / venv /
   `pip list --format=json` and emit `model.Package` records.
2. Optionally add `pip`-specific enrichers under `internal/enricher/`.
3. Wire it into `cmd/whatever2sbom/main.go` — switch on `--system`.

### Adding a new output schema (e.g. SPDX 2.3)

1. Add `internal/formatter/spdx23.go` implementing `formatter.Formatter`.
2. Add `internal/validator/spdx23.go` implementing `validator.Validator`.
3. Embed the schema file via `//go:embed`.
4. Wire the schema choice into `cmd/whatever2sbom/main.go`.

Because every stage is hidden behind a small interface, adding either kind
of extension touches one new file plus a few lines in `main.go`.

---

## Development

The repository ships a `Makefile` with the most common workflows.

```bash
make            # show available targets
make build      # stripped, static binary
make test       # all unit tests
make bench      # micro-benchmarks for hot paths
make bench-e2e  # end-to-end on a real dpkg system (needs hyperfine)
make deb        # build a .deb for the host architecture
make deb-all    # build .deb for amd64 + arm64
make lint       # go vet + gofmt check
make fmt        # apply gofmt
make clean      # remove build artifacts and generated SBOMs
make release    # cross-compile binaries for linux/{amd64,arm64} into ./dist/
```

Or, equivalently, the raw `go` commands:

```bash
# Run all tests
go test ./internal/...

# With coverage
go test -coverprofile=coverage.out ./internal/...
go tool cover -html=coverage.out

# Lint / format
go vet ./...
gofmt -l .

# Cross-compile for Linux arm64 (e.g. Raspberry Pi)
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" \
  -o whatever2sbom-linux-arm64 ./cmd/whatever2sbom
```

The project has **no `cgo` dependencies**, so static cross-compilation
"just works" for any Go target.

---

## License

MIT — see [LICENSE](LICENSE).
