# whatever2sbom

Generates a validated CycloneDX SBOM from a system or project.
Output is always validated against the selected schema before writing.

## Requirements

- Python 3.11+
- Linux with `dpkg` (Debian / Ubuntu) for `--system dpkg`

## Installation

```bash
pip install .
```

## Quick start

Scan the local system with all enrichment enabled (default):

```bash
whatever2sbom
```

Write to a specific file:

```bash
whatever2sbom -o /tmp/system.cdx.json
```

For the full set of options see the [CLI reference](cli-reference.md).

## Where to go next

- [Getting started](getting-started.md) — installation and a first scan
- [CLI reference](cli-reference.md) — all flags and product metadata options
- [Systems](systems.md) — what whatever2sbom can scan
- [Output format](output.md) — what ends up in the generated SBOM
- [Validation](validation.md) — schema validation and BSI TR-03183-2 compliance
- [Performance](performance.md) — benchmarks and tuning tips
