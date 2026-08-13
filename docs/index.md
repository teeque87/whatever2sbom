---
title: whatever2sbom
description: Generate a validated, BSI TR-03183-2-aware CycloneDX SBOM for whatever you throw at it — offline, with rich provenance.
---

# whatever2sbom

**whatever2sbom** generates a validated [CycloneDX](https://cyclonedx.org/) Software Bill of
Materials (SBOM) from a system or project. It scans an installed package database — Debian or
Ubuntu via `dpkg`/`apt`, a Python virtualenv via `pip`, or a Node.js project via `npm`'s
`package-lock.json` — enriches each component with hashes, licenses and provenance metadata, and
writes out a CycloneDX document that has already been checked against the official JSON schema — so
what you get is always structurally valid.

It can additionally check the result against the
[BSI TR-03183-2](https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Anforderungen-an-Hersteller/Hersteller_node.html)
v2.1.0 cyber-resilience SBOM requirements and report exactly which fields are missing for full
compliance.

!!! warning "BSI TR-03183-2 support is experimental"
    The `--bsi-tr-compliant` check is **experimental and not feature-complete**. It is opt-in
    (off by default) and **advisory only** — a clean report is not a certification or a guarantee
    of compliance, and the set of checks may change as it matures. See
    [Validation](validation.md#bsi-tr-03183-2-compliance) for details.

## Why whatever2sbom

- **Validated by default.** Every SBOM is checked against the bundled CycloneDX schema before it's
  written. There is no "trust me" mode — schema validation is always on and a failure is fatal.
- **Offline.** All schemas and reference data (CycloneDX, SPDX license list/expressions) are
  bundled with the package. No network access is required at runtime.
- **Rich provenance.** Components carry hashes (SHA-256/512/1, MD5), SPDX-classified licenses,
  copyright notices, supplier/author contacts, and a resolved dependency graph — not just a flat
  package list.
- **Compliance-aware (experimental).** `--bsi-tr-compliant` runs an additional, advisory check
  against BSI TR-03183-2 §5.2.2 and tells you precisely what's missing. This check is experimental
  and not yet feature-complete.
- **Built to be extended.** Scanning a new ecosystem (npm, …) or emitting a new output schema
  (SPDX, …) means writing one small plugin and registering it — see
  [Architecture](architecture.md) and [Extending whatever2sbom](extending.md).

## Requirements

- Python 3.11+
- Linux with `dpkg` (Debian / Ubuntu) for `--system dpkg`
- A virtualenv for `--system pip`
- A `package-lock.json` (npm ≥ 7) for `--system npm`

## Installation

```bash
pip install .
```

## Quick start

Scan the local system with all enrichment enabled (default):

```bash
whatever2sbom --product-supplier "Acme GmbH"
```

This writes `sbom_<timestamp>.cdx.json` in the current directory and prints a short summary
(component count, hash and license coverage) to stdout.

## Where to go next

- [Getting started](getting-started.md) — installation and a first scan
- [CLI reference](cli-reference.md) — all flags and product metadata options
- [Systems](systems/index.md) — what whatever2sbom can scan (`dpkg`, `npm`, `pip`)
- [Schemas](schemas.md) — the output formats it can emit (CycloneDX)
- [Output format](output.md) — what ends up in the generated SBOM
- [Validation](validation.md) — schema validation and BSI TR-03183-2 compliance
- [Architecture](architecture.md) — how a scan flows through the pipeline
- [Extending whatever2sbom](extending.md) — add a new system, formatter, or validator
- [Performance](performance.md) — benchmarks and tuning tips
