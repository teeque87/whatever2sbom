# `dpkg`

The default system (`--system dpkg`, or simply omit `--system`). Collects every installed package
from the local `dpkg` database and enriches it in two independent steps:

1. **Collection** (`dpkg-query`) — package identity, dependencies, maintainer, section/priority,
   and `Provides`/virtual package resolution.
2. **`apt-cache` enrichment** (skip with `--no-apt-cache`) — SHA-256/512/1 and MD5 hashes,
   download size, and the `.deb` pool filename, via `apt-cache show`.
3. **Copyright enrichment** (skip with `--no-licenses`) — SPDX license identifiers and copyright
   notices, parsed from `/usr/share/doc/<pkg>/copyright` (DEP-5 and legacy free-form formats).

## Options

| Option | Description |
|---|---|
| `--distro ID` | Override the distro identifier used in package PURLs (e.g. `ubuntu`, `debian`). Auto-detected from `/etc/os-release` if omitted. |
| `--no-apt-cache` | Skip `apt-cache show` enrichment. Hashes and download metadata will be absent for most packages. |
| `--no-licenses` | Skip reading copyright files. The `licenses` field will be empty on all components. |
| `--exclude PATTERN` | Exclude an installed package from the SBOM. Repeatable; merged with `--exclude-file`. See [Excluding packages](#excluding-packages). |
| `--exclude-file FILE` | File of packages to exclude, one per line. Merged with any `--exclude` values. |

## Excluding packages

Use `--exclude` / `--exclude-file` to drop packages from the SBOM entirely — useful when certain
packages must not appear in the inventory at all.

A pattern is either an **exact package name**, or a **glob** when it contains `*`, `?`, or `[...]`:

| Pattern | Matches |
|---|---|
| `snapd` | exactly `snapd` (not `snapd-glib`) |
| `linux-image-*` | `linux-image-6.8.0-generic`, `linux-image-unsigned-6.8.0`, … |
| `*-dbg` | any debug-symbol package |

Matching is **case-sensitive** and applied to the bare package name (the `:arch` qualifier of
multi-arch packages is already stripped). Exact matching is intentionally literal — exclusion is
destructive, so a short name never silently sweeps up a whole family; reach for a glob when you mean
one.

Inline and file patterns are merged, so small lists fit on the command line and long ones live in a
file:

```bash
whatever2sbom --product-supplier "Acme" \
  --exclude snapd \
  --exclude 'linux-image-*' \
  --exclude-file ./excludes.txt
```

In an `--exclude-file`, one pattern per line; blank lines and `#` comments (whole-line or trailing)
are ignored, so the list can record *why* each entry is excluded:

```
# shipped and managed outside this image
linux-image-*
snapd          # replaced by a native package

*-dbg          # debug symbols never belong in the delivered SBOM
```

Exclusion happens **before** the dependency graph and the synthetic
[source components](../output.md#synthetic-source-components) are built: dependency edges to an
excluded package are dropped (no dangling references), and a source group left empty by exclusion
produces no source component. Excluding a source package by name (or glob) also removes its synthetic
source component. Any pattern that matches **no** installed package is reported as a warning on
stderr, so typos surface instead of silently doing nothing.

## `metadata.component`

- **Without `--product-name`**: `metadata.component` describes the scanned operating system
  itself (type `operating-system`, name/version/description from `/etc/os-release`). This is the
  default for a plain `whatever2sbom --product-supplier "..."` run — fitting, since `dpkg` scans
  every installed package on that OS, including the kernel and base system.
- **With `--product-name`**: `metadata.component` describes your product instead, and becomes the
  root of the dependency tree. Its CycloneDX `type` also defaults to `operating-system`; pass
  `--product-type firmware` if the scanned system is itself a firmware/appliance image (a common
  case for BSI TR-03183-2).

See [Getting started](../getting-started.md) for full examples.
