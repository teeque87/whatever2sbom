"""
Central registry for system plugins, formatters, and validators.

How to add a new ecosystem (e.g. pip):
    1. Create src/whatever2sbom/systems/pip.py with a PipSystem(SystemPlugin).
    2. Add  register_system(PipSystem())  at the bottom of this file.

How to add a new output schema (e.g. SPDX):
    1. Create src/whatever2sbom/formatters/spdx23.py  and
              src/whatever2sbom/validators/spdx_validator.py.
    2. Add  register_formatter("spdx", "2.3", SpdxFormatter)
            register_validator("spdx", "2.3", SpdxValidator)  at the bottom.
"""

from __future__ import annotations

import inspect

from whatever2sbom.formatters.base import Formatter
from whatever2sbom.systems.base import SystemPlugin
from whatever2sbom.validators.base import Validator

# ── internal registries ───────────────────────────────────────────────────────

_SYSTEMS: dict[str, SystemPlugin] = {}
_FORMATTERS: dict[tuple[str, str], type[Formatter]] = {}
_VALIDATORS: dict[tuple[str, str], type[Validator]] = {}


# ── registration helpers ──────────────────────────────────────────────────────

def register_system(plugin: SystemPlugin) -> None:
    _SYSTEMS[plugin.name] = plugin


def register_formatter(schema: str, version: str, cls: type[Formatter]) -> None:
    _FORMATTERS[(schema.lower(), version)] = cls


def register_validator(schema: str, version: str, cls: type[Validator]) -> None:
    _VALIDATORS[(schema.lower(), version)] = cls


# ── lookup helpers ────────────────────────────────────────────────────────────

def get_system(name: str) -> SystemPlugin:
    if name not in _SYSTEMS:
        raise ValueError(
            f"Unknown --system {name!r}. Available: {sorted(_SYSTEMS)}"
        )
    return _SYSTEMS[name]


def get_formatter(schema: str, version: str, **kwargs) -> Formatter:
    """
    Instantiate the formatter registered for (schema, version).

    Extra kwargs are forwarded to the formatter's __init__ only when the
    constructor actually declares that parameter, so callers can safely pass
    options that not every formatter needs (e.g. distro).
    """
    key = (schema.lower(), version)
    if key not in _FORMATTERS:
        available = sorted(f"{s}/{v}" for s, v in _FORMATTERS)
        raise ValueError(
            f"No formatter for --schema {schema!r} --spec-version {version!r}. "
            f"Available: {available}"
        )
    cls = _FORMATTERS[key]
    accepted = set(inspect.signature(cls.__init__).parameters) - {"self"}
    return cls(**{k: v for k, v in kwargs.items() if k in accepted})


def get_validator(schema: str, version: str) -> Validator:
    key = (schema.lower(), version)
    if key not in _VALIDATORS:
        available = sorted(f"{s}/{v}" for s, v in _VALIDATORS)
        raise ValueError(
            f"No validator for --schema {schema!r} --spec-version {version!r}. "
            f"Available: {available}"
        )
    return _VALIDATORS[key]()


# ── introspection helpers (used by cli.py to build dynamic choices) ───────────

def system_names() -> list[str]:
    return sorted(_SYSTEMS)


def schema_names() -> list[str]:
    return sorted({s for s, _ in _FORMATTERS})


def spec_versions_for(schema: str) -> list[str]:
    return sorted({v for s, v in _FORMATTERS if s == schema.lower()})


def default_schema() -> str:
    """Return the schema name of the first registered formatter."""
    if not _FORMATTERS:
        raise RuntimeError("No formatters registered")
    return next(iter(_FORMATTERS))[0]


def default_spec_version(schema: str | None = None) -> str:
    """Return the first registered spec version for the given (or default) schema."""
    s = schema or default_schema()
    versions = spec_versions_for(s)
    if not versions:
        raise RuntimeError(f"No spec versions registered for schema {s!r}")
    return versions[0]


def output_extension_for(schema: str) -> str:
    """Return the output file extension declared by the formatter for this schema."""
    for (s, _), cls in _FORMATTERS.items():
        if s == schema.lower():
            return getattr(cls, "output_extension", "json")
    return "json"


# ── built-in registrations ────────────────────────────────────────────────────
# Keep these at the bottom so the functions above are defined first.
# Schema name and spec version are read from class attributes — the class is
# the single source of truth for its own identity.

from whatever2sbom.formatters.cyclonedx16 import CycloneDXFormatter          # noqa: E402
from whatever2sbom.systems.dpkg import DpkgSystem                            # noqa: E402
from whatever2sbom.validators.jsonschema_validator import CycloneDXSchemaValidator  # noqa: E402

register_system(DpkgSystem())
register_formatter(CycloneDXFormatter.schema_name, CycloneDXFormatter.spec_version, CycloneDXFormatter)
register_validator(CycloneDXSchemaValidator.schema_name, CycloneDXSchemaValidator.spec_version, CycloneDXSchemaValidator)
