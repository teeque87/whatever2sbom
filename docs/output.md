# Output format

The output is a CycloneDX BOM document (`.cdx.json`). This page describes the fields populated for
each component when scanning `dpkg`; other systems may populate a different subset (see
[`PackageRecord`](architecture.md#the-packagerecord-model) for which fields are ecosystem-agnostic).

## Component fields

- **`bom-ref`** — unique per-binary coordinate used as the dependency graph node id:
  `pkg:deb/<distro>/<binary_name>@<binary_version>?arch=<arch>&distro=<codename>`
- **`purl`** — matchable coordinate that vulnerability scanners (OSV.dev, Grype, …) key on.
  OSV/Ubuntu advisories are published against the **source** package with `arch=source`, so the
  coordinate depends on whether a package *is* its own source
  (see [below](#source-coordinate-matching)):
    - **package is its own source** (`source_name == name`, or no distinct source):
      `pkg:deb/<distro>/<name>@<source_version>?arch=source&distro=<codename>` — OSV matches it.
    - **built from a different source**:
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

### Source-coordinate matching

OSV.dev and the Ubuntu/Debian security trackers publish advisories against the **source** package,
identified with `arch=source` — e.g. `pkg:deb/ubuntu/php8.1@8.1.2-1ubuntu2.22?arch=source&distro=jammy`.
Binary package names (what you `apt install`) are **not** the match key. Dependency-Track follows
the same model, using the `distro` qualifier to select the OS release before matching against OSV.

This creates a tension. Many binary packages are built from one source package (e.g. `python3.12`,
`python3.12-minimal`, `python3.12-venv`, `libpython3.12-stdlib`, `libpython3.12-minimal`,
`libpython3.12t64` all come from source `python3.12`). They share one *source-level* CVE identity,
so emitting the `arch=source` coordinate on every one of them makes a PURL-keyed scanner report the
same vulnerability once per binary — unusable noise.

whatever2sbom resolves this **per package**, with no extra synthetic components:

- A package that **is its own source** (its binary name equals the source name, or it has no
  distinct source — e.g. `bash`, `python3.12`, `openssl`) carries the `arch=source` coordinate that
  advisories are keyed on. OSV matches it, exactly once.
- A binary built from a **different** source (`libpython3.12-stdlib` → source `python3.12`) carries
  its own binary coordinate plus an informational `upstream=<source_name>` qualifier. OSV does not
  match on binary names or `upstream`, so this binary never re-matches the source advisory — that is
  what stops the per-binary duplication.

This is **best-effort**: when a source package ships *no* binary of the same name (e.g. source
`nvidia-graphics-drivers-590` → `libnvidia-cfg1-590`, …; source `glibc` → `libc6`/`libc-bin`), none
of its installed binaries carry the source coordinate, so its advisories won't match. We
deliberately do **not** invent a "source" component for software that isn't installed — the SBOM
describes what is actually on the system. Debian's binary/source split can't be matched losslessly
without that compromise, and OSV/DT's source-only keying is a known rough edge of the ecosystem.

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
