# Systems and schemas

## Systems

A "system" is what `--system` selects: the ecosystem to scan. Each system contributes its own
collector (gathers raw package data), enrichers (add hashes, licenses, etc.), and CLI options.

### `dpkg`

The default system. Collects every installed package from the local `dpkg` database and enriches
it in two independent steps:

1. **Collection** (`dpkg-query`) — package identity, dependencies, maintainer, section/priority,
   and `Provides`/virtual package resolution.
2. **`apt-cache` enrichment** (skip with `--no-apt-cache`) — SHA-256/512/1 and MD5 hashes,
   download size, and the `.deb` pool filename, via `apt-cache show`.
3. **Copyright enrichment** (skip with `--no-licenses`) — SPDX license identifiers and copyright
   notices, parsed from `/usr/share/doc/<pkg>/copyright` (DEP-5 and legacy free-form formats).

| Option | Description |
|---|---|
| `--distro ID` | Override the distro identifier used in package PURLs (e.g. `ubuntu`, `debian`). Auto-detected from `/etc/os-release` if omitted. |
| `--no-apt-cache` | Skip `apt-cache show` enrichment. Hashes and download metadata will be absent for most packages. |
| `--no-licenses` | Skip reading copyright files. The `licenses` field will be empty on all components. |

Default product type for `metadata.component`: `firmware`.

### `pip`

Scans a Python virtualenv via `importlib.metadata` — no network access and no parsing of
`requirements.txt` (which can't express a real dependency graph).

1. **Venv discovery** — if `--venv-dir` isn't given, the venv is auto-detected by looking for a
   `pyvenv.cfg` file (the canonical PEP 405 marker, independent of directory naming): first
   `$VIRTUAL_ENV`, then `--project-dir` itself, then any single immediate subdirectory of
   `--project-dir` containing `pyvenv.cfg`. Ambiguous (multiple candidates) or missing cases raise
   an error telling you to pass `--venv-dir` explicitly.
2. **Collection** — every installed distribution under the venv's `site-packages`, with PURLs
   (`pkg:pypi/<name>@<version>`, PEP 503 normalized), homepage/issue URLs (from `Home-page` or
   `Project-URL`), and console-script detection for the `bsi:component:executable` property.
3. **License resolution** — tries, in order: PEP 639 `License-Expression`, the legacy `License`
   field, an unambiguous `License :: ...` Trove classifier, then recognizing standard license
   boilerplate (MIT/Apache-2.0/BSD-2/3-Clause/ISC/MPL-2.0/Unlicense) in a bundled `License-File`.
4. **Dependency graph** — built from each distribution's `Requires-Dist` entries
   (`dist.requires`), cross-referenced against the other installed packages. Requirements gated on
   `extra == "..."` (optional/dev/test extras, e.g. a package's own `pytest` under
   `extra == "testing"`) are excluded — including them produced false edges and dependency cycles.
   Other environment markers (`python_version`, `sys_platform`, …) are evaluated against the
   *running* interpreter.

If `--product-name` matches one of the scanned packages (e.g. scanning a project's own venv, which
includes the project itself), that package is excluded from `metadata.component`'s dependencies as
a self-reference, and the root's `dependsOn` is that package's own resolved `Requires-Dist` —  not
every installed package.

| Option | Description |
|---|---|
| `--venv-dir PATH` | Path to the virtualenv to scan. Must contain `pyvenv.cfg`. |
| `--project-dir PATH` | Project root to search for a virtualenv when `--venv-dir` is not given (default: current directory). |

Default product type for `metadata.component`: `application`.

Want to scan something else (npm, a container image, …)? See
[Extending whatever2sbom](extending.md#adding-a-new-system) — adding a system is the most common
extension.

## Schemas

`--schema` selects the output document format; `--spec-version` selects which version of that
format's specification to target.

| Format | Versions | Notes |
|---|---|---|
| `cyclonedx` | `1.6` | Default. Produces a `.cdx.json` file, validated against the bundled CycloneDX 1.6 JSON schema. |

Adding a new schema (e.g. SPDX) or a new spec version of an existing one (e.g. CycloneDX 1.7) is
covered in [Extending whatever2sbom](extending.md#adding-a-new-output-schema).
