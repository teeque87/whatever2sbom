# whatever2sbom

**whatever2sbom** generates a validated [CycloneDX](https://cyclonedx.org/) Software Bill of
Materials from a running system or a project. It scans an installed package database, enriches each
component with the metadata a useful SBOM actually needs, and writes a document that has already
been checked against the official CycloneDX JSON schema — so what you get out is always structurally
valid.

It can additionally measure the result against the
[BSI TR-03183-2](https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Anforderungen-an-Hersteller/Hersteller_node.html)
v2.1.0 cyber-resilience requirements and report exactly which fields are missing for full
compliance.

> [!WARNING]
> The BSI TR-03183-2 check (`--bsi-tr-compliant`) is **experimental and not feature-complete**.
> It is opt-in (off by default) and advisory only — a clean report is not a certification or a
> guarantee of compliance, and the set of checks may change as it matures.

## What it does

- **Scans real package state.** Debian/Ubuntu systems via `dpkg`/`apt`, a Python virtualenv via
  `pip`, or a Node.js project via `npm`'s `package-lock.json` — reading what is actually installed
  or pinned, not a manifest of what was requested.
- **Enriches every component.** Hashes (SHA-256/512/1, MD5), SPDX-classified licenses, copyright
  notices, supplier and author contacts, and a resolved dependency graph — not just a flat list of
  names and versions.
- **Validates before writing.** Every run is checked against the bundled CycloneDX schema. There is
  no "trust me" mode; a schema failure is fatal and nothing is written.
- **Runs offline.** All schemas and reference data (CycloneDX, the SPDX license list and
  expressions) ship with the tool. No network access at runtime, by design.
- **Checks compliance (experimental).** An optional pass reports which BSI TR-03183-2 data fields
  are present or missing, as a guideline for measuring an SBOM against the standard. This check is
  **experimental and not feature-complete** — advisory only, and not a certification or a guarantee
  of compliance.
- **Extends cleanly.** New ecosystems and output schemas are added as small, self-contained pieces,
  and the finished document can be post-processed by optional plugins (for example, rewriting
  package-URL namespaces) without touching the core.

## Status and roadmap

whatever2sbom is usable today for `dpkg`-, `pip`-, and `npm`-based systems emitting CycloneDX 1.6.
On the near-term roadmap:

- **npm enrichment** — layering per-package metadata (descriptions, homepages, authors) from
  `node_modules` on top of the lockfile-only baseline.
- **CycloneDX 1.7** — emitting and validating against the newer spec version alongside 1.6.

## Documentation

Full documentation — installation, the complete CLI reference, supported systems and schemas, the
output format, BSI TR-03183-2 compliance checking, the plugin system, performance notes, and guides
for extending the tool — lives at:

**https://teeque87.github.io/whatever2sbom/**
