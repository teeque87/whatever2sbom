# Output format

The output is a CycloneDX BOM document (`.cdx.json`). This page describes the fields populated for
each component when scanning `dpkg`; other systems may populate a different subset (see
[`PackageRecord`](architecture.md#the-packagerecord-model) for which fields are ecosystem-agnostic).

## Component fields

- **`bom-ref`** — unique per-binary coordinate used as the dependency graph node id:
  `pkg:deb/<distro>/<binary_name>@<binary_version>?arch=<arch>&distro=<codename>`
- **`purl`** — matchable coordinate that vulnerability scanners (OSV.dev, Grype, …) key on.
  Because Debian binary packages built from one source share a single source-level
  vulnerability identity, the source coordinate is emitted on only **one** binary per source group
  (the carrier — see [below](#source-coordinate-de-duplication)):
    - **carrier**: `pkg:deb/<distro>/<source_name>@<source_version>?arch=source&distro=<codename>`
    - **other binaries from the same source**:
      `pkg:deb/<distro>/<binary_name>@<binary_version>?arch=<arch>&upstream=<source_name>&distro=<codename>`
- **`name`, `version`** — binary package identity
- **`type`** — derived from the dpkg section (`library`, `application`, `firmware`,
  `operating-system`)
- **`scope`** — `required` for essential/important packages, `optional` otherwise
- **`supplier`** — maintainer name and email parsed from the `Maintainer` field (the entity that
  built/distributes the package, e.g. "Ubuntu Developers")
- **`authors`** — name and email parsed from the `Original-Maintainer` field when present (the
  Debian packager, often closer to upstream than Ubuntu's generic "Ubuntu Developers"), falling
  back to `Maintainer` (best-effort substitute for upstream author info, which dpkg does not track)
- **`copyright`** — copyright notice from the `Files: *` stanza of the DEP-5 copyright file (when
  available)
- **`licenses`** — SPDX identifiers extracted from the DEP-5 copyright file (when available), each
  with a `url` pointing to `https://spdx.org/licenses/<id>.html` and `acknowledgement: "declared"`
  per BSI TR-03183-2's "Original licences" mapping
- **`hashes`** — SHA-256, SHA-512, SHA-1, MD5 (populated by `apt-cache` enrichment)
- **`externalReferences`** — homepage, bug tracker
- **`properties`** — additional dpkg metadata: `dpkg:section`, `dpkg:priority`,
  `dpkg:installed-size`, `dpkg:download-size`, `dpkg:source`, `dpkg:source-name`,
  `dpkg:source-version`, `dpkg:origin`, `dpkg:multi-arch`; also
  `bsi:component:effectiveLicense` (Table 12, optional) — the SPDX expression for all declared
  licenses combined with `AND`, emitted when every declared license is itself SPDX-compliant
- **`dependencies`** — direct `Depends` and `Pre-Depends`, with virtual package names resolved via
  `Provides`

### `bom-ref` vs. `purl`

These differ for packages that have a distinct source package — e.g. `poppler-utils` is the binary
but `poppler` is the source that OSV/Ubuntu advisories are published against. For packages with no
distinct source, both fields use the binary name and version.

### Source-coordinate de-duplication

Many binary packages are built from a single source package (e.g. `python3.12`,
`python3.12-minimal`, `python3.12-venv`, `libpython3.12-stdlib`, `libpython3.12-minimal`,
`libpython3.12t64` all come from source `python3.12`). They share one *source-level* CVE identity,
so emitting the `arch=source` coordinate on every one of them makes a PURL-keyed scanner
(Dependency-Track, OSV) report the same vulnerability once per binary — unusable noise.

To keep detection working while removing the duplication, exactly **one** binary per source group
carries the `arch=source` coordinate that advisories are keyed on. The carrier is the installed
binary named exactly like the source package (e.g. `python3.12`), or — when no such binary is
installed (e.g. source `glibc` ships `libc6`/`libc-bin` but no `glibc` binary) — the
alphabetically-first member, chosen deterministically. Every other member keeps its own unique
binary coordinate plus an `upstream=<source_name>` qualifier (the Syft/Grype convention), so it
stays a distinct component, remains traceable to its source, and is not matched a second time.

`upstream` is a de-facto qualifier widely emitted by Syft/Grype/Trivy; it is not part of the
official `pkg:deb` spec, but PURL qualifiers are free-form `key=value` pairs, so it is spec-legal
and ignored by tools that do not understand it.

## Coverage statistics

`metadata.properties` includes overall coverage statistics for the scan:

```
sbom:total-components
sbom:hash-coverage / sbom:hash-coverage-pct
sbom:license-coverage / sbom:license-coverage-pct
```

These are also printed in the CLI summary after a successful run.
