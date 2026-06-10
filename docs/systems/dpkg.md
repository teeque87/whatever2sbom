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
