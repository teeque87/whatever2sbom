# whatever2sbom

Generates a validated CycloneDX SBOM from a system or project.
Output is always validated against the selected schema before writing.

📖 **Full documentation: https://teeque87.github.io/whatever2sbom/**

## Requirements

- Python 3.11+
- Linux with `dpkg` (Debian / Ubuntu) for `--system dpkg`

## Installation

```bash
pip install .
```

## Quick start

```bash
whatever2sbom --product-supplier "Acme GmbH"
```

See the [documentation](https://teeque87.github.io/whatever2sbom/) for the full CLI reference,
supported systems and schemas, output format, BSI TR-03183-2 compliance checking, performance
benchmarks, and a guide to extending whatever2sbom with new systems or output schemas.
