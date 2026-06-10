# CLI reference

```
whatever2sbom [--system SYSTEM] [--schema FORMAT] [--spec-version VERSION]
              [-o FILE] [-v] [--performance-metrics] [--bsi-tr-compliant]
              --product-supplier NAME [product metadata options]
              [system-specific options]
```

`--product-supplier` is the only required option; everything else has a sensible default.

## Global options

| Option | Default | Description |
|---|---|---|
| `--system SYSTEM` | `dpkg` | What to scan: `dpkg` or `pip`. See [Systems](systems.md). |
| `--schema FORMAT` | `cyclonedx` | Output schema format. See [Schemas](systems.md#schemas). |
| `--spec-version VERSION` | `1.6` | Spec version of the chosen schema. |
| `-o`, `--output FILE` | `sbom_<timestamp>.<ext>` | Output file path. Extension is chosen by the formatter (`.cdx.json` for CycloneDX). |
| `-v`, `--verbose` | off | Enable debug-level logging to stderr. |
| `--performance-metrics` | off | Print a timing breakdown of each pipeline stage (collect / enrich / format / validate / write) to stderr. |
| `--bsi-tr-compliant` | off | Additionally validate against the BSI TR-03183-2 v2.1.0 data-field requirements. Advisory — see [Validation](validation.md#bsi-tr-03183-2-compliance). |

## Product metadata (BSI TR-03183)

These describe the product or firmware image the SBOM is *about*, as opposed to the components
found inside it. `--product-supplier` is required; the rest are optional but recommended for BSI
TR-03183 compliance. When `--product-purl` is set, the product is also added as the root node of
the dependency tree.

| Option | Description |
|---|---|
| `--product-name NAME` | Name of the product or firmware image being described. |
| `--product-version VERSION` | Version of the product. |
| `--product-type TYPE` | CycloneDX component type (`firmware`, `application`, `container`, `device`, …). Default depends on `--system`: `firmware` for `dpkg`, `application` for `pip`. |
| `--product-supplier NAME` | **Required.** Supplier / vendor name (NTIA Supplier Name). |
| `--product-supplier-url URL` | Supplier URL. May be given multiple times. |
| `--product-purl PURL` | Package-URL identifying the product, e.g. `pkg:generic/acme/fw@1.0`. Adds the product as the dependency-tree root. |
| `--author 'Name <email>'` | SBOM author. May be given multiple times. Populates `metadata.authors`. |

## `dpkg` system options

Active when `--system dpkg` (the default). See [Systems](systems.md#dpkg) for what each enrichment
step does.

| Option | Description |
|---|---|
| `--distro ID` | Override the distro identifier used in package PURLs (e.g. `ubuntu`, `debian`). Auto-detected from `/etc/os-release` if omitted. |
| `--no-apt-cache` | Skip `apt-cache show` enrichment. Hashes and download metadata will be absent for most packages. |
| `--no-licenses` | Skip reading `/usr/share/doc/<pkg>/copyright`. The `licenses` field will be empty on all components. |

## `pip` system options

Active when `--system pip`. See [Systems](systems.md#pip) for venv discovery and dependency
resolution details.

| Option | Description |
|---|---|
| `--venv-dir PATH` | Path to the virtualenv to scan (default: auto-detect a directory containing `pyvenv.cfg` under `--project-dir`, or `$VIRTUAL_ENV`). |
| `--project-dir PATH` | Project root to search for a virtualenv when `--venv-dir` is not given (default: current directory). |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | SBOM written successfully (a non-empty `--bsi-tr-compliant` report does **not** change this). |
| `1` | Configuration error (e.g. unknown `--schema`/`--spec-version` combination), schema validation failure, or a runtime error during collection/enrichment/formatting. |
