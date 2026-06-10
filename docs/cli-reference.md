# CLI reference

```
whatever2sbom [--system SYSTEM] [--schema FORMAT] [--spec-version VERSION]
              [-o FILE] [-v] [--bsi-tr-compliant]
              [dpkg options]
```

## Global options

| Option | Default | Description |
|---|---|---|
| `--system SYSTEM` | `dpkg` | What to scan. See [Systems](systems.md). |
| `--schema FORMAT` | `cyclonedx` | Output schema format. See [Schemas](systems.md#schemas). |
| `--spec-version VERSION` | `1.6` | Spec version of the chosen schema. |
| `-o, --output FILE` | `sbom_<timestamp>.cdx.json` | Output file path. |
| `-v, --verbose` | off | Enable debug-level logging to stderr. |
| `--bsi-tr-compliant` | off | Additionally validate against the BSI TR-03183-2 v2.1.0 data-field requirements (SPDX licences, SHA-512 hashes, creator contact info, executable/archive/structured properties, dependency completeness, …). See [BSI TR-03183-2 compliance](validation.md#bsi-tr-03183-2-compliance). |

## Product metadata (BSI TR-03183)

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

## dpkg-specific options

| Option | Description |
|---|---|
| `--distro ID` | Override the distro identifier used in package PURLs (e.g. `ubuntu`, `debian`). Auto-detected from `/etc/os-release` if omitted. |
| `--no-apt-cache` | Skip `apt-cache show` enrichment. Hashes and download metadata will be absent for most packages. |
| `--no-licenses` | Skip reading copyright files. The `licenses` field will be empty on all components. |
