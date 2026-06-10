# Systems and schemas

## Systems

A "system" is what `--system` selects: the ecosystem to scan. Each system contributes its own
collector (gathers raw package data), enrichers (add hashes, licenses, etc.), and CLI options.

| System | Default for | `--product-name` | Default product type | `metadata.component` | Description |
|---|---|---|---|---|---|
| [`dpkg`](dpkg.md) | `--system` (default) | Optional | `operating-system` | The product if `--product-name` is set, else the scanned host OS (from `/etc/os-release`) | Local Debian/Ubuntu `dpkg` database |
| [`pip`](pip.md) | — | **Required** | `application` | Always the product named by `--product-name` | A Python virtualenv |

"Default product type" is the CycloneDX `type` for `metadata.component` when `--product-name` is
given but `--product-type` is not.

Whether `--product-name` is required depends on the system: for `dpkg`, the thing being scanned
*is* the host OS, so it can fall back to describing that OS (type `operating-system`) and
`--product-name` is optional. For `pip`, scanning a virtualenv has nothing to do with the host
OS, so there's no meaningful fallback — `--product-name` is required, and the CLI rejects
`--system pip` without it.

Want to scan something else (npm, a container image, …)? See
[Extending whatever2sbom](../extending.md#adding-a-new-system) — adding a system is the most
common extension.

## Schemas

`--schema` selects the output document format; `--spec-version` selects which version of that
format's specification to target.

| Format | Versions | Notes |
|---|---|---|
| `cyclonedx` | `1.6` | Default. Produces a `.cdx.json` file, validated against the bundled CycloneDX 1.6 JSON schema. |

Adding a new schema (e.g. SPDX) or a new spec version of an existing one (e.g. CycloneDX 1.7) is
covered in [Extending whatever2sbom](../extending.md#adding-a-new-output-schema).
