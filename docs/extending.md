# Extending whatever2sbom

This guide walks through the three ways whatever2sbom is meant to be extended: a new **system**
(scan a different ecosystem), a new **output schema** (emit something other than CycloneDX), and a
new **spec version** of an existing schema. If you haven't already, read
[Architecture](architecture.md) first — it explains the pipeline and the registry these examples
plug into.

All built-in implementations live under `src/whatever2sbom/` and are good references: `dpkg.py`
for a system, `cyclonedx16.py` for a formatter, `jsonschema_validator.py` and `bsi_tr03183.py` for
validators.

## Adding a new system

A system is "an ecosystem you can pass to `--system`" — for example `pip`, `npm`, or a container
image scanner. It's made of three pieces: a `Collector`, zero or more `Enricher`s, and a
`SystemPlugin` that wires them together and declares any extra CLI flags.

### 1. Write the collector

The collector's only job is to produce a list of [`PackageRecord`](architecture.md#the-packagerecord-model)
objects. Populate as many fields as your ecosystem naturally provides — leave the rest at their
defaults (`None` / empty list).

```python
# src/whatever2sbom/collectors/pip.py
import json
import subprocess

from whatever2sbom.collectors.base import Collector
from whatever2sbom.models import PackageRecord
from whatever2sbom import purl as _purl


class PipCollector(Collector):
    name = "pip"

    def collect(self) -> list[PackageRecord]:
        raw = subprocess.run(
            ["pip", "list", "--format=json"],
            capture_output=True, text=True, check=True,
        ).stdout
        packages = []
        for entry in json.loads(raw):
            pkg_purl = f"pkg:pypi/{entry['name'].lower()}@{entry['version']}"
            packages.append(PackageRecord(
                name=entry["name"],
                version=entry["version"],
                purl=pkg_purl,
                bom_ref=pkg_purl,
                component_type="library",
            ))
        return packages
```

A few conventions worth following:

- **`purl` and `bom_ref`** are the collector's responsibility (see
  [Architecture](architecture.md#the-packagerecord-model)) — formatters emit them verbatim. If
  your ecosystem has no separate "source package" concept, `purl` and `bom_ref` can be the same.
- **`component_type`** and **`scope`** drive the CycloneDX `type`/`scope` fields. Map them from
  whatever classification your ecosystem provides; default to `"library"` / `"required"` if there
  isn't one.
- Anything that doesn't map to an existing `PackageRecord` field goes in `extra_properties` as
  `(name, value)` tuples, e.g. `[("pip:editable", "true")]`.

### 2. Write enrichers (optional)

Enrichers add data the collector doesn't have, without changing the collector. They're useful for
expensive or optional steps (network calls, extra subprocess invocations, file reads) that a user
might want to skip with a flag.

```python
# src/whatever2sbom/enrichers/pip_licenses.py
from whatever2sbom.enrichers.base import Enricher
from whatever2sbom.models import PackageRecord


class PipLicenseEnricher(Enricher):
    name = "pip-licenses"

    def enrich(self, packages: list[PackageRecord]) -> list[PackageRecord]:
        for pkg in packages:
            license_id = _read_license_metadata(pkg.name, pkg.version)
            if license_id:
                pkg.licenses.append(license_id)
        return packages


def _read_license_metadata(name: str, version: str) -> str | None:
    ...
```

Enrichers run in the order returned by `make_enrichers` and mutate/replace the list in place — an
enricher that depends on data from an earlier one (e.g. "only fetch hashes for packages that don't
have one yet") just needs to run after it in that list.

### 3. Write the system plugin

The plugin ties the collector and enrichers together and declares any CLI options under its own
argument group. CLI flags are received as `argparse.Namespace`; use `getattr(args, "...", default)`
for anything optional so the plugin still works if its `add_arguments` wasn't called (e.g. in
tests).

```python
# src/whatever2sbom/systems/pip.py
import argparse

from whatever2sbom.collectors.pip import PipCollector
from whatever2sbom.enrichers.pip_licenses import PipLicenseEnricher
from whatever2sbom.systems.base import SystemPlugin


class PipSystem(SystemPlugin):
    name = "pip"
    description = "Installed Python packages (pip list)"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        grp = parser.add_argument_group("pip system options")
        grp.add_argument(
            "--no-licenses",
            action="store_true",
            help="Skip license metadata lookup",
        )

    def make_collector(self, args: argparse.Namespace) -> PipCollector:
        return PipCollector()

    def make_enrichers(self, args: argparse.Namespace) -> list:
        if getattr(args, "no_licenses", False):
            return []
        return [PipLicenseEnricher()]
```

### 4. Register it

Add one line to the bottom of `registry.py`:

```python
from whatever2sbom.systems.pip import PipSystem
register_system(PipSystem())
```

`--system pip` is now available, `--help` lists it automatically (`system_names()` is read from
the registry), and the "pip system options" argument group appears in `--help` whenever it's
registered.

### 5. Test it

Add a test under `tests/` following the existing `dpkg` tests as a template — typically:

- a unit test for the collector against a fixed/mocked subprocess output
- a unit test for each enricher
- an end-to-end test running the pipeline with `--system pip` against fixture data and asserting
  the output validates against the schema

## Adding a new output schema

A schema is "what `--schema`/`--spec-version` selects" — a `Formatter` that turns
`list[PackageRecord]` into a document, plus a `Validator` that checks that document.

### 1. Write the formatter

```python
# src/whatever2sbom/formatters/spdx23.py
from whatever2sbom.formatters.base import Formatter
from whatever2sbom.models import PackageRecord


class SpdxFormatter(Formatter):
    schema_name = "spdx"
    spec_version = "2.3"
    output_extension = "spdx.json"

    name = "spdx-2.3"

    def __init__(self, product_name: str | None = None, **_ignored) -> None:
        self.product_name = product_name

    def format(self, packages: list[PackageRecord]) -> dict:
        return {
            "spdxVersion": "SPDX-2.3",
            "name": self.product_name or "system",
            "packages": [_to_spdx_package(pkg) for pkg in packages],
            # ...
        }


def _to_spdx_package(pkg: PackageRecord) -> dict:
    return {
        "name": pkg.name,
        "versionInfo": pkg.version,
        "SPDXID": f"SPDXRef-{pkg.name}-{pkg.version}",
        # ...
    }
```

`schema_name`, `spec_version`, and `output_extension` are class attributes the registry and CLI
read directly — they're the single source of truth for `--schema spdx --spec-version 2.3` and the
default output filename (`sbom_<timestamp>.spdx.json`).

`get_formatter()` inspects your `__init__` signature and only forwards the kwargs it actually
declares, so you can accept just the product-metadata fields your format needs (here, only
`product_name`) and ignore the rest via `**_ignored`.

### 2. Write the validator

```python
# src/whatever2sbom/validators/spdx_validator.py
from whatever2sbom.validators.base import Validator


class SpdxValidator(Validator):
    schema_name = "spdx"
    spec_version = "2.3"

    name = "spdx-2.3-jsonschema"

    def validate(self, bom: dict) -> list[str]:
        errors = []
        if "spdxVersion" not in bom:
            errors.append("missing required field: spdxVersion")
        return errors
```

Return a list of human-readable error strings; an empty list means the document is valid. A
non-empty list raises `ValidationError` in the pipeline and aborts the run before anything is
written — schema validation is always fatal.

If you're validating against a JSON Schema, follow `jsonschema_validator.py`'s pattern: bundle the
schema file under `src/whatever2sbom/schema/`, list it in
`pyproject.toml`'s `[tool.setuptools.package-data]`, and load it relative to `__file__` so it works
from an installed wheel with no network access.

### 3. Register both

```python
from whatever2sbom.formatters.spdx23 import SpdxFormatter
from whatever2sbom.validators.spdx_validator import SpdxValidator

register_formatter(SpdxFormatter.schema_name, SpdxFormatter.spec_version, SpdxFormatter)
register_validator(SpdxValidator.schema_name, SpdxValidator.spec_version, SpdxValidator)
```

`--schema spdx --spec-version 2.3` is now selectable, and `--schema spdx` alone works once `2.3`
is the only (or first) registered version for `spdx`.

## Adding a new spec version of an existing schema

For a new CycloneDX release (e.g. 1.7) that mostly extends 1.6:

1. Drop the new `bom-1.7.schema.json` (and an updated `spdx.schema.json`, if it changed) into
   `src/whatever2sbom/schema/cdx/`.
2. Subclass the formatter and validator with `spec_version = "1.7"`, overriding only what actually
   changed:

   ```python
   class CycloneDXFormatter17(CycloneDXFormatter):
       spec_version = "1.7"

       def format(self, packages: list[PackageRecord]) -> dict:
           bom = super().format(packages)
           bom["specVersion"] = "1.7"
           # ... add/adjust whatever changed in 1.7
           return bom
   ```

   `CycloneDXSchemaValidator` already derives its schema path from `spec_version`
   (`schema/cdx/bom-<spec_version>.schema.json`), so a bare subclass with just the new
   `spec_version` is often enough on the validator side.

3. Register both:

   ```python
   register_formatter("cyclonedx", "1.7", CycloneDXFormatter17)
   register_validator("cyclonedx", "1.7", CycloneDXSchemaValidator17)
   ```

`--spec-version 1.7` now appears automatically in `--help` (`spec_versions_for("cyclonedx")` reads
the registry), alongside the existing `1.6`.

## Checklist

Whatever you're adding, the registry is the only place new pieces need to be wired in —
everything else (`--help` choices, defaults, output extensions) is derived from it:

- [ ] Implement the base class (`Collector`, `Enricher`, `SystemPlugin`, `Formatter`, or
      `Validator`) in the matching package.
- [ ] Register it at the bottom of `registry.py`.
- [ ] Bundle any reference data (schemas, license lists, …) under `src/whatever2sbom/schema/` and
      list it in `pyproject.toml`'s `package-data` — runtime stays offline, no exceptions.
- [ ] Add tests under `tests/`.
- [ ] Document new CLI options in [CLI reference](cli-reference.md) and new systems/schemas in
      [Systems and schemas](systems/index.md).
