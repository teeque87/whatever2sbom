# Systems and schemas

## Systems

A "system" is what `--system` selects: the ecosystem to scan. Each system contributes its own
collector (gathers raw package data), enrichers (add hashes, licenses, etc.), and CLI options.

### `dpkg`

The default and currently only system. Collects every installed package from the local `dpkg`
database and enriches it in two independent steps:

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

Want to scan something else (pip, npm, a container image, …)? See
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
