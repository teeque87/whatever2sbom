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
              [-o FILE] [-v]
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

### Product metadata (BSI TR-03183)

To produce a BSI TR-03183 compliant SBOM, supply at minimum `--product-name` and `--product-purl`.
All options are optional; omitting them falls back to an OS-based `metadata.component`.

| Option | Description |
|---|---|
| `--product-name NAME` | Name of the product or firmware image being described. |
| `--product-version VERSION` | Version of the product. |
| `--product-type TYPE` | CycloneDX component type (e.g. `firmware`, `application`, `container`, `device`). Default: `firmware`. |
| `--product-supplier NAME` | Supplier / vendor name. |
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

## Output

Each component in the SBOM contains:

- `name`, `version`, `purl` — package identity
- `type` — derived from the dpkg section (`library`, `application`, `firmware`, `operating-system`)
- `scope` — `required` for essential/important packages, `optional` otherwise
- `supplier` — maintainer name and email parsed from the `Maintainer` field
- `licenses` — SPDX identifiers extracted from the DEP-5 copyright file (when available)
- `hashes` — SHA-256, SHA-512, SHA-1, MD5 (populated by apt-cache enrichment)
- `externalReferences` — homepage, bug tracker, pool download path
- `properties` — additional dpkg metadata: `dpkg:section`, `dpkg:priority`, `dpkg:installed-size`, `dpkg:download-size`, `dpkg:source`, `dpkg:origin`, `dpkg:multi-arch`
- `dependencies` — direct `Depends` and `Pre-Depends`, with virtual package names resolved via `Provides`

The BOM metadata includes coverage statistics as properties:

```
sbom:total-components
sbom:hash-coverage / sbom:hash-coverage-pct
sbom:license-coverage / sbom:license-coverage-pct
```
