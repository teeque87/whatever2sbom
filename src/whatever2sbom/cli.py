"""
CLI entry point for whatever2sbom.

Global flags control what to scan (--system) and how to format + validate the
output (--schema / --spec-version).  System-specific flags (e.g. --distro for
dpkg) are added dynamically by each registered SystemPlugin.

Validation against the chosen schema is always performed — there is no opt-out.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

import whatever2sbom
from whatever2sbom import registry
from whatever2sbom.pipeline import SbomPipeline
from whatever2sbom.validators.base import ValidationError


def _build_parser() -> argparse.ArgumentParser:
    # All choices and defaults come from the registry — nothing is hardcoded here.
    systems         = registry.system_names()
    schemas         = registry.schema_names()
    default_schema  = registry.default_schema()
    default_version = registry.default_spec_version()

    p = argparse.ArgumentParser(
        prog=whatever2sbom.__title__,
        description=(
            "Generate a validated SBOM for whatever you throw at it.\n\n"
            "Validation against the chosen schema is always performed."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # ── global scan / output options ──────────────────────────────────────────
    p.add_argument(
        "--system",
        choices=systems,
        default=systems[0] if systems else "dpkg",
        metavar="SYSTEM",
        help=f"What to scan. Available: {', '.join(systems)}  (default: {systems[0] if systems else 'dpkg'})",
    )
    p.add_argument(
        "--schema",
        choices=schemas,
        default=default_schema,
        metavar="FORMAT",
        help=f"SBOM output schema format. Available: {', '.join(schemas)}  (default: {default_schema})",
    )
    p.add_argument(
        "--spec-version",
        default=default_version,
        metavar="VERSION",
        dest="spec_version",
        help=f"Schema specification version  (default: {default_version})",
    )
    p.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Write SBOM to FILE  (default: sbom_<timestamp>.<ext>)",
    )
    p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug-level logging",
    )

    # ── system-specific option groups ─────────────────────────────────────────
    # Each registered SystemPlugin declares its own arguments here, so the CLI
    # stays clean when new systems are added.
    for name in systems:
        registry.get_system(name).add_arguments(p)

    return p


def _default_filename(schema: str) -> str:
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = registry.output_extension_for(schema)
    return f"sbom_{ts}.{ext}"


def main(argv: list[str] | None = None) -> None:
    args = _build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)-8s %(message)s",
        stream=sys.stderr,
    )

    # ── resolve pipeline components ───────────────────────────────────────────
    try:
        system    = registry.get_system(args.system)
        # Forward all parsed args as kwargs; registry filters to accepted params.
        formatter = registry.get_formatter(
            args.schema,
            args.spec_version,
            distro=getattr(args, "distro", None),
        )
        validator = registry.get_validator(args.schema, args.spec_version)
    except ValueError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        sys.exit(1)

    collector = system.make_collector(args)
    enrichers = system.make_enrichers(args)

    # ── run pipeline (validation is always included) ──────────────────────────
    pipeline = SbomPipeline(
        collector=collector,
        enrichers=enrichers,
        formatter=formatter,
        validators=[validator],
    )

    try:
        bom = pipeline.run()
    except ValidationError as exc:
        print(
            f"Schema validation failed ({len(exc.errors)} error(s)):",
            file=sys.stderr,
        )
        for err in exc.errors:
            print(f"  {err}", file=sys.stderr)
        sys.exit(1)
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    # ── write output ──────────────────────────────────────────────────────────
    output = args.output or _default_filename(args.schema)
    Path(output).write_text(
        json.dumps(bom, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    # ── summary ───────────────────────────────────────────────────────────────
    meta  = bom.get("metadata", {})
    props = {p["name"]: p["value"] for p in meta.get("properties", [])}

    print(f"SBOM written → {output}")
    print(f"  system          : {args.system}")
    print(f"  schema          : {args.schema} {args.spec_version}")
    for key, label in (
        ("sbom:total-components",    "total components"),
        ("sbom:hash-coverage-pct",   "hash coverage"),
        ("sbom:license-coverage-pct","license coverage"),
    ):
        if key in props:
            print(f"  {label:<16}: {props[key]}")


if __name__ == "__main__":
    main()
