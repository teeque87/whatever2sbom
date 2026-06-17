# `npm`

Scans a Node.js project from its `package-lock.json` (`--system npm`) — no network access and no
call to `npm` itself. The lockfile is read directly, so the SBOM reflects exactly the versions npm
resolved and pinned.

This is a **best-effort, lockfile-only** collector: everything comes from `package-lock.json`.
Richer per-package metadata (descriptions, homepages, authors) lives in each
`node_modules/<pkg>/package.json` and is left for a future enricher — mirroring how `dpkg` starts
from `dpkg-query` and layers `apt-cache`/copyright enrichment on top.

## Lockfile discovery

`--lockfile` may point at the `package-lock.json` file itself **or** at a directory to search (so
`--lockfile ./my-project` works like a project root). When a directory is searched — including the
current directory, used when `--lockfile` is omitted — the top-level `package-lock.json` is tried
first, then npm's "hidden" `node_modules/.package-lock.json` (the copy npm keeps inside an
installed tree, same lockfileVersion 3 format).

Only `lockfileVersion` **2 and 3** are supported — both key installed packages under the
`packages` map. The legacy `lockfileVersion 1` (npm ≤ 6), which only carries a nested
`dependencies` tree, is rejected with an error telling you to regenerate with npm ≥ 7.

## Collection

Every entry under the lockfile's `packages` map (each `node_modules/<pkg>` install), with:

- **PURLs** — `pkg:npm/<name>@<version>`; scoped packages put the scope in the PURL namespace with
  its `@` percent-encoded (`@angular/core` → `pkg:npm/%40angular/core@<version>`).
- **Hashes** — the `integrity` SRI digest (`sha512-…`), base64-decoded to the hex form CycloneDX
  expects. SHA-512 satisfies the BSI TR-03183-2 hash requirement.
- **`bsi:component:filename`** — the deployable artifact's filename, taken from the `resolved`
  tarball URL (e.g. `…/lodash-4.17.21.tgz` → `lodash-4.17.21.tgz`). Skipped for git/file/link
  dependencies, which have no registry tarball.
- **`bsi:component:executable`** — `executable` if the entry declares a `bin`, else
  `non-executable`. An installed package is an unpacked directory (`non-archive`, `structured`),
  not an executable archive.
- **`npm:deprecated`** — the deprecation message, when the lockfile records one.

The root project entry (`""`) and `link` entries (workspace symlinks) are skipped; the root is the
product (`metadata.component`), not an installed dependency.

## Scope mapping

The npm install flags in the lockfile map to the CycloneDX component `scope`:

| Lockfile flag | Scope | Meaning |
|---|---|---|
| `dev` / `devOptional` | `excluded` | Present in `node_modules` but not in the deployed runtime. |
| `optional` | `optional` | An npm optional dependency. |
| (none) | `required` | A production dependency. |

Pass `--exclude-dev-dependencies` to drop `dev`/`devOptional` entries entirely (and any edges
pointing at them) rather than emitting them as `excluded`.

## License resolution

Taken from the lockfile entry's `license` field — normally an SPDX expression string (e.g. `MIT`,
`(MIT OR Apache-2.0)`). The legacy `license` object (`{type, url}`), a list of such objects, and
the old plural `licenses` array are all accepted. `UNLICENSED` (npm's marker for proprietary / no
license) is dropped rather than emitted. License strings are classified for SPDX compliance the
same way as every other system (see [Validation](../validation.md)).

## Dependency graph

Built by resolving each package's `dependencies` and `optionalDependencies` against the
actually-installed tree, following Node's module resolution: the nearest `node_modules` (the
package's own, for deduped/nested installs) wins, walking up toward the project root. This uses the
lockfile's path keys, so nested copies of a package at different versions resolve to the correct
node.

- **`peerDependencies` are not graph edges** — they're constraints on the consumer's tree (usually
  already satisfied by another listed package), not "this package installed that one".
- A dependency that resolves to an excluded entry (e.g. under `--exclude-dev-dependencies`) is
  dropped rather than left dangling.

## Product metadata

`--product-name`, `--product-version`, `--product-type`, etc. come **only from the CLI
arguments** — whatever2sbom does not read `package.json` for product metadata.

**`--product-name` is required for `--system npm`.** Like `pip`, a scanned Node.js project isn't
the host OS, so there's no accurate fallback for `metadata.component` — the CLI exits with an error
if `--product-name` is missing. If `--product-type` is omitted, the product defaults to type
`application`.

## Options

| Option | Description |
|---|---|
| `--lockfile PATH` | Path to `package-lock.json`, or a directory to search (default: current directory; tries `package-lock.json`, then `node_modules/.package-lock.json`). |
| `--exclude-dev-dependencies` | Omit `devDependencies` (lockfile entries marked `dev`/`devOptional`). |

## Example

```bash
whatever2sbom --system npm \
  --lockfile ./my-app \
  --product-name my-app \
  --product-version "1.2.3" \
  --product-supplier "Acme GmbH" \
  -o my-app.cdx.json
```

Production dependencies only:

```bash
whatever2sbom --system npm --lockfile ./my-app/package-lock.json \
  --exclude-dev-dependencies \
  --product-name my-app --product-supplier "Acme GmbH"
```
