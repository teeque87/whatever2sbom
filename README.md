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
whatever2sbom
```

See the [documentation](https://teeque87.github.io/whatever2sbom/) for the full CLI reference,
supported systems and schemas, output format, BSI TR-03183-2 compliance checking, and
performance benchmarks.

> See the [Go port](https://github.com/teeque87/whatever2sbom/tree/go-port) for a single static
> binary that runs the same pipeline 3–23× faster with no Python runtime required.
