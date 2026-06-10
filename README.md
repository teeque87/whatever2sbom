# whatever2sbom

Generates a validated CycloneDX SBOM from a system or project.  
Output is always validated against the selected schema before writing.

## Requirements

- Python 3.11+
- Linux with `dpkg` (Debian / Ubuntu) for `--system dpkg`

## Installation

```bash
pip install .
```

## Usage

```
whatever2sbom [--system SYSTEM] [--schema FORMAT] [--spec-version VERSION]
              [-o FILE] [-v] [--bsi-tr-compliant]
              [dpkg options]
```

### Global options

| Option | Default | Description |
|---|---|---|
| `--system SYSTEM` | `dpkg` | What to scan. See [Systems](#systems). |
| `--schema FORMAT` | `cyclonedx` | Output schema format. See [Schemas](#schemas). |
| `--spec-version VERSION` | `1.6` | Spec version of the chosen schema. |
| `-o, --output FILE` | `sbom_<timestamp>.cdx.json` | Output file path. |
| `-v, --verbose` | off | Enable debug-level logging to stderr. |
| `--bsi-tr-compliant` | off | Additionally validate against the BSI TR-03183-2 v2.1.0 data-field requirements (SPDX licences, SHA-512 hashes, creator contact info, executable/archive/structured properties, dependency completeness, …). See [BSI TR-03183-2 compliance](#bsi-tr-03183-2-compliance). |

### Product metadata (BSI TR-03183)

To produce a BSI TR-03183 compliant SBOM, supply at minimum `--product-name` and `--product-purl`.
All options are optional; omitting them falls back to an OS-based `metadata.component`.

| Option | Description |
|---|---|
| `--product-name NAME` | Name of the product or firmware image being described. |
| `--product-version VERSION` | Version of the product. |
| `--product-type TYPE` | CycloneDX component type (e.g. `firmware`, `application`, `container`, `device`). Default: `firmware`. |
| `--product-supplier NAME` | **Required.** Supplier / vendor name (NTIA Supplier Name). |
| `--product-supplier-url URL` | Supplier URL. May be given multiple times. |
| `--product-purl PURL` | Package-URL that uniquely identifies the product, e.g. `pkg:generic/acme/fw@1.0`. When set, the product is also added as the root node of the dependency tree. |
| `--author 'Name <email>'` | SBOM author. May be given multiple times. Populates `metadata.authors`. |

### Systems

#### `dpkg`

Collects all installed packages from the local dpkg database, enriches them
with hashes from `apt-cache`, and extracts license information from
`/usr/share/doc/<pkg>/copyright`.

| Option | Description |
|---|---|
| `--distro ID` | Override the distro identifier used in package PURLs (e.g. `ubuntu`, `debian`). Auto-detected from `/etc/os-release` if omitted. |
| `--no-apt-cache` | Skip `apt-cache show` enrichment. Hashes and download metadata will be absent for most packages. |
| `--no-licenses` | Skip reading copyright files. The `licenses` field will be empty on all components. |

### Schemas

| Format | Versions | Notes |
|---|---|---|
| `cyclonedx` | `1.6` | Default. Produces a `.cdx.json` file. |

## Examples

Scan the local system with all enrichment enabled (default):

```bash
whatever2sbom
```

Write to a specific file:

```bash
whatever2sbom -o /tmp/system.cdx.json
```

Scan a Ubuntu system where the distro was not auto-detected correctly:

```bash
whatever2sbom --distro ubuntu
```

Skip license extraction for a faster run:

```bash
whatever2sbom --no-licenses -o fast.cdx.json
```

Verbose output to follow the pipeline:

```bash
whatever2sbom -v
```

BSI TR-03183 compliant SBOM for a firmware image:

```bash
whatever2sbom \
  --product-name "AcmeFW" \
  --product-version "2.4.1" \
  --product-type firmware \
  --product-supplier "Acme GmbH" \
  --product-supplier-url "https://acme.example.com" \
  --product-purl "pkg:generic/acme/acmefw@2.4.1" \
  --author "Jane Doe <jane@acme.example.com>" \
  -o acmefw.cdx.json
```

## Performance

End-to-end wall-clock on **Ubuntu 26.04**, 5-run average via [hyperfine](https://github.com/sharkdp/hyperfine) (1 warmup excluded):

```bash
sudo apt install hyperfine
make bench-e2e
```

| Configuration | Wall-clock | σ |
|---|---:|---:|
| `--no-licenses --no-apt-cache` — dpkg collect + format + validate only | **3.804 s** | ± 0.158 s |
| `--no-licenses` — + apt-cache hash enrichment | **9.092 s** | ± 1.279 s |
| full pipeline — + DEP-5 copyright extraction | **8.362 s** | ± 0.269 s |

The dominant cost in all three cases is `apt-cache show` (15+ subprocess calls for hash enrichment) and Python interpreter startup overhead. Pass `--no-apt-cache` when you only need package identity and don't require download hashes.

> See the [Go port](https://github.com/teeque87/whatever2sbom/tree/go-port) for a single static binary that runs the same pipeline **3–23× faster** with no Python runtime required.

## Output

Each component in the SBOM contains:

- `bom-ref` — unique per-binary coordinate used as the dependency graph node id:
  `pkg:deb/<distro>/<binary_name>@<binary_version>?arch=<arch>&distro=<codename>`
- `purl` — matchable source coordinate that vulnerability scanners (OSV.dev, Grype, …) key on:
  `pkg:deb/<distro>/<source_name>@<source_version>?arch=source&distro=<codename>`
- `name`, `version` — binary package identity
- `type` — derived from the dpkg section (`library`, `application`, `firmware`, `operating-system`)
- `scope` — `required` for essential/important packages, `optional` otherwise
- `supplier` — maintainer name and email parsed from the `Maintainer` field
- `authors` — maintainer name and email parsed from the `Maintainer` field (best-effort substitute for upstream author info, which dpkg does not track)
- `copyright` — copyright notice from the `Files: *` stanza of the DEP-5 copyright file (when available)
- `licenses` — SPDX identifiers extracted from the DEP-5 copyright file (when available), each with a `url` pointing to the corresponding `https://spdx.org/licenses/<id>.html` page and `acknowledgement: "declared"` per BSI TR-03183-2's "Original licences" mapping
- `evidence.occurrences` — the `.deb` pool path, also used for `bsi:component:filename`; this is what Dependency-Track shows as the component's "Filename" in its Extended details
- `hashes` — SHA-256, SHA-512, SHA-1, MD5 (populated by apt-cache enrichment)
- `externalReferences` — homepage, bug tracker, pool download path
- `properties` — additional dpkg metadata: `dpkg:section`, `dpkg:priority`, `dpkg:installed-size`, `dpkg:download-size`, `dpkg:source`, `dpkg:source-name`, `dpkg:source-version`, `dpkg:origin`, `dpkg:multi-arch`; also `bsi:component:effectiveLicense` (Table 12, optional) — the SPDX expression for all declared licenses combined with `AND`, emitted when every declared license is itself SPDX-compliant
- `dependencies` — direct `Depends` and `Pre-Depends`, with virtual package names resolved via `Provides`

The `bom-ref` and `purl` differ for packages that have a distinct source package (e.g. `poppler-utils`
is the binary but `poppler` is the source that OSV/Ubuntu advisories are published against). For
packages with no distinct source, both fields use the binary name and version.

The BOM metadata includes coverage statistics as properties:

```
sbom:total-components
sbom:hash-coverage / sbom:hash-coverage-pct
sbom:license-coverage / sbom:license-coverage-pct
```

## Validation

The bundled CycloneDX 1.6 JSON schema and the SPDX license expression schema are embedded in the
package — no network access is required at runtime. Validation always runs; there is no opt-out.

### BSI TR-03183-2 compliance

Every CycloneDX SBOM already includes the BSI TR-03183-2 §5.2.2 component fields: SPDX-classified
licences (`license.id` / `expression`, falling back to `LicenseRef-*` or a plain `name` when no
SPDX match exists), the `bsi:component:filename`, `bsi:component:executable`,
`bsi:component:archive` and `bsi:component:structured` properties, and a `compositions` entry
marking dependency-completeness as `unknown` (resolution may drop unsatisfied/virtual
dependencies).

Pass `--bsi-tr-compliant` to additionally check the produced SBOM against the BSI TR-03183-2
v2.1.0 data-field requirements: SBOM/component creator contact info (e-mail or URL), SPDX-only
licences, SHA-512 hashes of deployable components, the properties above, and absence of
vulnerability data. This is opt-in because not every environment can supply all required data
(e.g. a SHA-512 for every package, or a maintainer e-mail for every component) — the check
reports exactly what's missing.

This check is **advisory**: findings are printed to stderr as a compliance report, but the
SBOM is still written even if some components don't pass. On a real system, packages with
license metadata that isn't expressible as an SPDX identifier/expression (e.g. `"various"`,
`"public-domain"`) will reliably show up here — the report tells you exactly which components
and fields fall short of full compliance so you can fix what's in your control and document
the rest. Schema validation (always on, not gated by this flag) remains fatal — that catches
structural bugs in the SBOM itself.
