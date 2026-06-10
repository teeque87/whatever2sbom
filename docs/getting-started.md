# Getting started

## Requirements

- Python 3.11+
- Linux with `dpkg` (Debian / Ubuntu) for `--system dpkg`

## Installation

/// tab | From a checkout
```bash
pip install .
```
///

/// tab | Development
```bash
make venv
```

Creates a `.venv` with `whatever2sbom` installed in editable mode plus test dependencies — see the
[`Makefile`](https://github.com/teeque87/whatever2sbom/blob/main/Makefile).
///

## Your first scan

The only required option is `--product-supplier` (the BSI TR-03183 "NTIA Supplier Name"):

```bash
whatever2sbom --product-supplier "Acme GmbH"
```

This:

1. Collects every installed `dpkg` package on the local system.
2. Enriches each package with hashes and download metadata from `apt-cache`, and license/copyright
   data from `/usr/share/doc/<pkg>/copyright`.
3. Formats the result as a CycloneDX 1.6 document.
4. Validates it against the bundled CycloneDX JSON schema (fatal on failure).
5. Writes `sbom_<timestamp>.cdx.json` and prints a summary.

## Common variations

#### Write to a specific file

```bash
whatever2sbom --product-supplier "Acme GmbH" -o /tmp/system.cdx.json
```

#### Override the distro identifier

Useful if `/etc/os-release` doesn't match the package repository, e.g. a derivative distro:

```bash
whatever2sbom --product-supplier "Acme GmbH" --distro ubuntu
```

#### Skip license extraction

Faster — skips reading and parsing `/usr/share/doc/*/copyright`:

```bash
whatever2sbom --product-supplier "Acme GmbH" --no-licenses -o fast.cdx.json
```

#### Skip all `apt-cache` enrichment

Fastest option, but no hashes or download metadata:

```bash
whatever2sbom --product-supplier "Acme GmbH" --no-apt-cache --no-licenses -o minimal.cdx.json
```

#### Verbose logging

Follow each pipeline stage as it runs:

```bash
whatever2sbom --product-supplier "Acme GmbH" -v
```

#### Performance metrics

Print a per-stage timing breakdown (collect / enrich / format / validate):

```bash
whatever2sbom --product-supplier "Acme GmbH" --performance-metrics
```

## A fully described, BSI TR-03183-compliant SBOM

For firmware/product SBOMs you'll usually want to describe the product itself (so it becomes the
root of the dependency tree) and pass `--bsi-tr-compliant` to get a compliance report:

```bash
whatever2sbom \
  --product-name "AcmeFW" \
  --product-version "2.4.1" \
  --product-type firmware \
  --product-supplier "Acme GmbH" \
  --product-supplier-url "https://acme.example.com" \
  --product-purl "pkg:generic/acme/acmefw@2.4.1" \
  --author "Jane Doe <jane@acme.example.com>" \
  --bsi-tr-compliant \
  -o acmefw.cdx.json
```

If anything is missing for full compliance (e.g. a component without an SPDX-expressible
license), the findings are summarized on stderr and written in full to
`acmefw.bsi-report.txt` — the SBOM is still written either way.

See [CLI reference](cli-reference.md) for every available option and
[Validation](validation.md) for what `--bsi-tr-compliant` checks and why it's advisory.
