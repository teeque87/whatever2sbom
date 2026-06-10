# Getting started

## Requirements

- Python 3.11+
- Linux with `dpkg` (Debian / Ubuntu) for `--system dpkg`

## Installation

```bash
pip install .
```

## Basic usage

```
whatever2sbom [--system SYSTEM] [--schema FORMAT] [--spec-version VERSION]
              [-o FILE] [-v] [--bsi-tr-compliant]
              [dpkg options]
```

### Examples

Scan the local system with all enrichment enabled (default):

```bash
whatever2sbom
```

Write to a specific file:

```bash
whatever2sbom -o /tmp/system.cdx.json
```

Scan a Ubuntu system where the distro was not auto-detected correctly:

```bash
whatever2sbom --distro ubuntu
```

Skip license extraction for a faster run:

```bash
whatever2sbom --no-licenses -o fast.cdx.json
```

Verbose output to follow the pipeline:

```bash
whatever2sbom -v
```

### BSI TR-03183 compliant SBOM for a firmware image

```bash
whatever2sbom \
  --product-name "AcmeFW" \
  --product-version "2.4.1" \
  --product-type firmware \
  --product-supplier "Acme GmbH" \
  --product-supplier-url "https://acme.example.com" \
  --product-purl "pkg:generic/acme/acmefw@2.4.1" \
  --author "Jane Doe <jane@acme.example.com>" \
  -o acmefw.cdx.json
```

See [CLI reference](cli-reference.md) for all available options and
[Validation](validation.md) for what `--bsi-tr-compliant` checks.
