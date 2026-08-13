# Architecture

whatever2sbom is built around a small pipeline and a registry of pluggable pieces. Understanding
this is the first step before [extending](extending.md) it.

## The pipeline

Every run builds and executes a `SbomPipeline`
([`pipeline.py`](https://github.com/teeque87/whatever2sbom/blob/main/src/whatever2sbom/pipeline.py)):

```
Collector  →  Enricher (0..n)  →  Formatter  →  Plugin (0..n)  →  Validator (1..n)
```

1. **Collector** — gathers raw package data from one ecosystem (e.g. the local `dpkg` database)
   and returns a list of [`PackageRecord`](#the-packagerecord-model) objects.
2. **Enrichers** — each takes the list of `PackageRecord`s and returns an updated list, adding
   information the collector didn't have (hashes, licenses, …). Enrichers run in order and are
   independent of each other.
3. **Formatter** — converts the enriched `PackageRecord`s into the final output document (a dict
   that gets serialized to JSON), e.g. a CycloneDX 1.6 BOM.
4. **Plugins** — optional post-processing scripts (enabled with `--plugin`) that take the formatted
   document and return a modified one. They run last but *before* validation, so anything they emit
   is still schema-checked. None run unless `--plugin` is given. See [Plugins](plugins.md).
5. **Validators** — check the formatted document. Schema validation always runs and is fatal
   (`ValidationError` aborts the run before anything is written).

```python
class SbomPipeline:
    def run(self) -> dict:
        packages = self.collector.collect()
        for enricher in self.enrichers:
            packages = enricher.enrich(packages)
        bom = self.formatter.format(packages)
        for plugin in self.plugins:
            bom = plugin.run(bom)
        for validator in self.validators:
            errors = validator.validate(bom)
            if errors:
                raise ValidationError(errors)
        return bom
```

## The registry

[`registry.py`](https://github.com/teeque87/whatever2sbom/blob/main/src/whatever2sbom/registry.py)
is the single source of truth for what's available:

- **Systems** (`register_system`) — one per ecosystem, keyed by name (`"dpkg"`, `"npm"`, `"pip"`). Selected
  via `--system`.
- **Formatters** (`register_formatter`) — keyed by `(schema, spec_version)`, e.g.
  `("cyclonedx", "1.6")`. Selected via `--schema`/`--spec-version`.
- **Validators** (`register_validator`) — keyed the same way as formatters, and run alongside the
  matching formatter.

`cli.py` builds its `argparse` choices (`--system`, `--schema`, available `--spec-version`s,
default file extension, …) entirely from what's registered — nothing is hardcoded. Registering a
new system/formatter/validator automatically makes it selectable on the command line.

Post-processing [plugins](plugins.md) are the exception: they aren't registered here. They're
discovered by filename across a search path at runtime (`--plugin <name>`), so adding one is just
dropping a `.py` file in a plugin directory — no code change or registration needed.

## A `SystemPlugin` ties it together

A [`SystemPlugin`](https://github.com/teeque87/whatever2sbom/blob/main/src/whatever2sbom/systems/base.py)
is the unit of "an ecosystem you can scan". It has four jobs:

- declare any CLI options it needs (`add_arguments`)
- build its `Collector` from the parsed args (`make_collector`)
- build its ordered list of `Enricher`s from the parsed args (`make_enrichers`)
- declare the default CycloneDX component type for `metadata.component` (`default_product_type`)

The built-in `DpkgSystem` registers `--distro`, `--no-apt-cache`, and `--no-licenses`, builds a
`DpkgCollector`, conditionally adds `AptCacheEnricher` and `CopyrightEnricher`, and inherits the
base `default_product_type` of `"operating-system"`.

`PipSystem` registers `--venv-dir` and `--project-dir`, builds a `PipCollector` (which resolves
licenses and the dependency graph itself, so it has no enrichers), and defaults
`default_product_type` to `"application"`.

## The `PackageRecord` model

[`PackageRecord`](https://github.com/teeque87/whatever2sbom/blob/main/src/whatever2sbom/models.py)
is the uniform representation of "one package" that flows between collectors, enrichers, and
formatters. It's a single dataclass covering identity, provenance, hashes, licenses, dependency
graph references, and CycloneDX-specific classification (`component_type`, `scope`,
`bsi_executable`/`bsi_archive`/`bsi_structured`).

Two fields are worth calling out because they're computed by the **collector**, not the
formatter:

- **`purl`** — the matchable coordinate a vulnerability scanner keys on (for `dpkg`: the
  `arch=source` coordinate when a package is its own source, else the binary coordinate +
  `upstream=<source>`, plus a synthetic `arch=source` component for sources with no same-named
  binary — see [Output format](output.md#source-coordinate-matching); for `pip`:
  `pkg:pypi/<name>@<version>` with the name PEP 503 normalized).
- **`bom_ref`** — a unique dependency-graph node id (for `dpkg`: the per-binary coordinate
  including `arch`; for `pip`: the same PURL, since each installed distribution is unique).

Formatters emit `purl`/`bom_ref` verbatim and never construct PURLs themselves — this keeps
ecosystem-specific PURL rules (which differ a lot between deb, npm, pip, …) out of the formatter,
so the same `CycloneDXFormatter` works for every system.

`extra_properties` is the escape hatch for ecosystem-specific metadata that doesn't fit anywhere
else (e.g. `("npm:deprecated", "use foo instead")`) — formatters emit these as CycloneDX
`properties` verbatim.

## Where things live

| Concept | Base class | Built-in implementation |
|---|---|---|
| System plugin | `systems/base.py::SystemPlugin` | `systems/dpkg.py::DpkgSystem`, `systems/npm.py::NpmSystem`, `systems/pip.py::PipSystem` |
| Collector | `collectors/base.py::Collector` | `collectors/dpkg.py::DpkgCollector`, `collectors/npm.py::NpmCollector`, `collectors/pip.py::PipCollector` |
| Enricher | `enrichers/base.py::Enricher` | `enrichers/apt_cache.py`, `enrichers/copyright.py` |
| Formatter | `formatters/base.py::Formatter` | `formatters/cyclonedx16.py::CycloneDXFormatter` |
| Validator | `validators/base.py::Validator` | `validators/jsonschema_validator.py::CycloneDXSchemaValidator`, `validators/bsi_tr03183.py::BsiTr03183Validator` |
| Plugin | `plugins/base.py` (`apply(bom, config)` contract) | `plugins/builtin/patch-purl.py` |

Continue to [Extending whatever2sbom](extending.md) for step-by-step guides and code examples for
each of these.
