# Output format

The output is a CycloneDX BOM document (`.cdx.json`). This page describes the fields populated for
each component when scanning `dpkg`; other systems may populate a different subset (see
[`PackageRecord`](architecture.md#the-packagerecord-model) for which fields are ecosystem-agnostic).

## Component fields

- **`bom-ref`** — unique per-binary coordinate used as the dependency graph node id:
  `pkg:deb/<distro>/<binary_name>@<binary_version>?arch=<arch>&distro=<codename>`
- **`purl`** — matchable source coordinate that vulnerability scanners (OSV.dev, Grype, …) key on:
  `pkg:deb/<distro>/<source_name>@<source_version>?arch=source&distro=<codename>`
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

## Coverage statistics

`metadata.properties` includes overall coverage statistics for the scan:

```
sbom:total-components
sbom:hash-coverage / sbom:hash-coverage-pct
sbom:license-coverage / sbom:license-coverage-pct
```

These are also printed in the CLI summary after a successful run.
