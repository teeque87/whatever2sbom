# CLI reference

```
whatever2sbom [--system SYSTEM] [--schema FORMAT] [--spec-version VERSION]
              [-o FILE] [-v] [--performance-metrics] [--bsi-tr-compliant]
              --product-supplier NAME [product metadata options]
              [--plugin NAME ...] [--plugin-config NAME:KEY=VALUE ...]
              [--plugin-config-file FILE]
              [system-specific options]
```

`--product-supplier` is the only required option; everything else has a sensible default.

## Global options

| Option | Default | Description |
|---|---|---|
| `--system SYSTEM` | `dpkg` | What to scan: `dpkg`, `npm`, or `pip`. See [Systems](systems/index.md). |
| `--schema FORMAT` | `cyclonedx` | Output schema format. See [Schemas](schemas.md). |
| `--spec-version VERSION` | `1.6` | Spec version of the chosen schema. |
| `-o`, `--output FILE` | `sbom_<timestamp>.<ext>` | Output file path. Extension is chosen by the formatter (`.cdx.json` for CycloneDX). |
| `-v`, `--verbose` | off | Enable debug-level logging to stderr. |
| `--performance-metrics` | off | Print a timing breakdown of each pipeline stage (collect / enrich / format / validate / write) to stderr. |
| `--bsi-tr-compliant` | off | **Experimental, not feature-complete.** Additionally validate against the BSI TR-03183-2 v2.1.0 data-field requirements. Advisory — see [Validation](validation.md#bsi-tr-03183-2-compliance). |

## Product metadata (BSI TR-03183)

These describe the product or firmware image the SBOM is *about*, as opposed to the components
found inside it. `--product-supplier` is required for every system; the rest are optional but
recommended for BSI TR-03183 compliance. When `--product-purl` is set, the product is also added
as the root node of the dependency tree.

`--product-name` is additionally **required for systems that don't scan the host OS** (currently
`npm` and `pip`) — without it, there's nothing for `metadata.component` to describe, since (unlike
`dpkg`) the scanned thing isn't the host OS and can't fall back to `/etc/os-release`.

| Option | Description |
|---|---|
| `--product-name NAME` | Name of the product or firmware image being described. Optional for `dpkg` (falls back to describing the host OS); **required** for `npm` and `pip`. |
| `--product-version VERSION` | Version of the product. |
| `--product-type TYPE` | CycloneDX component type (`firmware`, `application`, `container`, `device`, `operating-system`, …) for `metadata.component` *when `--product-name` is set*. Default depends on `--system`: `operating-system` for `dpkg`, `application` for `npm`/`pip`. (For `dpkg` without `--product-name`, `metadata.component` describes the host OS, type `operating-system`, regardless of this option.) |
| `--product-supplier NAME` | **Required.** Supplier / vendor name (NTIA Supplier Name). |
| `--product-supplier-url URL` | Supplier URL. May be given multiple times. |
| `--product-supplier-email EMAIL` | Supplier contact e-mail address. Satisfies the BSI TR-03183-2 creator-contact requirement (§3.2.2 / §5.2.1). |
| `--product-purl PURL` | Package-URL identifying the product, e.g. `pkg:generic/acme/fw@1.0`. Adds the product as the dependency-tree root. |
| `--author 'Name <email>'` | SBOM author. May be given multiple times. Populates `metadata.authors`. |

## Plugins

Optional post-processing scripts that run **last** — after formatting, just before schema
validation, so their output is still validated. See the [Plugins guide](plugins.md) for how to
write one and how plugin files are discovered.

| Option | Description |
|---|---|
| `--plugin NAME` | Enable a plugin by script name (without `.py`). May be given multiple times; plugins run in the order listed. |
| `--plugin-config NAME:KEY=VALUE` | Configure a plugin. May be given multiple times. A comma-separated `VALUE` becomes a list, e.g. `--plugin-config patch-purl:packages=bash,coreutils`. |
| `--plugin-config-file FILE` | JSON file mapping plugin name → config object. Merged *under* any inline `--plugin-config` values (which win on conflict). |

## System-specific options

Each system adds its own options. To keep `--help` focused as more systems are added, **`--help`
shows only the active system's options** — the default (`dpkg`) when `--system` is omitted, or the
one named by `--system`. To see another system's options, pass it alongside `--help`, e.g.
`whatever2sbom --system npm --help`. All systems' options are documented below.

### `dpkg` system options

Active when `--system dpkg` (the default). See [dpkg](systems/dpkg.md) for what each enrichment
step does.

| Option | Description |
|---|---|
| `--distro ID` | Override the distro identifier used in package PURLs (e.g. `ubuntu`, `debian`). Auto-detected from `/etc/os-release` if omitted. |
| `--no-apt-cache` | Skip `apt-cache show` enrichment. Hashes and download metadata will be absent for most packages. |
| `--no-licenses` | Skip reading `/usr/share/doc/<pkg>/copyright`. The `licenses` field will be empty on all components. |
| `--exclude PATTERN` | Exclude an installed package from the SBOM: an exact name or a glob (`*`, `?`, `[...]`), e.g. `linux-image-*`. Accepts a comma-separated list; repeatable; merged with `--exclude-file`. See [Excluding packages](systems/dpkg.md#excluding-packages). |
| `--exclude-file FILE` | File of packages to exclude, one name/glob per line (blank lines and `#` comments ignored). Merged with any `--exclude` values. |

### `npm` system options

Active when `--system npm`. See [npm](systems/npm.md) for lockfile discovery, scope mapping, and
dependency resolution details.

| Option | Description |
|---|---|
| `--lockfile PATH` | Path to `package-lock.json`, or a directory to search (default: current directory; tries `package-lock.json`, then npm's hidden `node_modules/.package-lock.json`). Only `lockfileVersion` 2/3 (npm ≥ 7) are supported. |
| `--exclude-dev-dependencies` | Omit `devDependencies` (lockfile entries marked `dev`/`devOptional`) and any edges pointing at them. Without it, dev packages are emitted with CycloneDX scope `excluded`. |

### `pip` system options

Active when `--system pip`. See [pip](systems/pip.md) for venv discovery and dependency
resolution details.

| Option | Description |
|---|---|
| `--venv-dir PATH` | Path to the virtualenv to scan (default: auto-detect a directory containing `pyvenv.cfg` under `--project-dir`). Must contain `pyvenv.cfg`. `$VIRTUAL_ENV` is not consulted. |
| `--project-dir PATH` | Project root to search for a virtualenv when `--venv-dir` is not given (default: current directory). |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | SBOM written successfully (a non-empty `--bsi-tr-compliant` report does **not** change this). |
| `1` | Configuration error (e.g. unknown `--schema`/`--spec-version` combination), a plugin error (not found, bad config, or a failure while running), schema validation failure, or a runtime error during collection/enrichment/formatting. |
