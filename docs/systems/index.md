# Systems

A "system" is what `--system` selects: the ecosystem to scan. Each system contributes its own
collector (gathers raw package data), enrichers (add hashes, licenses, etc.), and CLI options. What
the resulting document looks like is the same across systems — see [Schemas](../schemas.md) and
[Output format](../output.md).

| System | Default for | `--product-name` | Default product type | `metadata.component` | Description |
|---|---|---|---|---|---|
| [`dpkg`](dpkg.md) | `--system` (default) | Optional | `operating-system` | The product if `--product-name` is set, else the scanned host OS (from `/etc/os-release`) | Local Debian/Ubuntu `dpkg` database |
| [`npm`](npm.md) | — | **Required** | `application` | Always the product named by `--product-name` | A Node.js project's `package-lock.json` |
| [`pip`](pip.md) | — | **Required** | `application` | Always the product named by `--product-name` | A Python virtualenv |

"Default product type" is the CycloneDX `type` for `metadata.component` when `--product-name` is
given but `--product-type` is not.

Whether `--product-name` is required depends on the system: for `dpkg`, the thing being scanned
*is* the host OS, so it can fall back to describing that OS (type `operating-system`) and
`--product-name` is optional. For `pip` and `npm`, scanning a virtualenv or a Node.js project has
nothing to do with the host OS, so there's no meaningful fallback — `--product-name` is required,
and the CLI rejects those systems without it.

Want to scan something else (a container image, a Cargo project, …)? See
[Extending whatever2sbom](../extending.md#adding-a-new-system) — adding a system is the most
common extension.
