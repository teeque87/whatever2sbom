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
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

import whatever2sbom
from whatever2sbom import perf, registry
from whatever2sbom.pipeline import SbomPipeline
from whatever2sbom.validators.base import ValidationError
from whatever2sbom.validators.bsi_tr03183 import BsiTr03183Validator


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
    p.add_argument(
        "--performance-metrics",
        action="store_true",
        dest="performance_metrics",
        help="Print a timing breakdown of each pipeline stage to stderr",
    )
    p.add_argument(
        "--bsi-tr-compliant",
        action="store_true",
        dest="bsi_tr_compliant",
        help=(
            "Additionally validate the SBOM against the BSI TR-03183-2 v2.1.0 "
            "data-field requirements (SPDX licences, SHA-512 hashes, creator "
            "contact info, executable/archive/structured properties, …)"
        ),
    )

    # ── product metadata (BSI TR-03183) ──────────────────────────────────────
    prod = p.add_argument_group(
        "product metadata",
        "Describe the product/firmware being scanned (required for BSI TR-03183 compliance).",
    )
    prod.add_argument(
        "--product-name",
        metavar="NAME",
        help="Name of the product or firmware image being described",
    )
    prod.add_argument(
        "--product-version",
        metavar="VERSION",
        help="Version of the product",
    )
    prod.add_argument(
        "--product-type",
        metavar="TYPE",
        default=None,
        help=(
            "CycloneDX component type for the product "
            "(firmware | application | container | device | …)  "
            "(default: depends on --system, e.g. firmware for dpkg, application for pip)"
        ),
    )
    prod.add_argument(
        "--product-supplier",
        metavar="NAME",
        required=True,
        help="Supplier / vendor name (required — NTIA Supplier Name)",
    )
    prod.add_argument(
        "--product-supplier-url",
        metavar="URL",
        action="append",
        dest="product_supplier_url",
        help="Supplier URL (may be given multiple times)",
    )
    prod.add_argument(
        "--product-purl",
        metavar="PURL",
        help="Package-URL that uniquely identifies the product (e.g. pkg:generic/acme/fw@1.0)",
    )
    prod.add_argument(
        "--author",
        metavar="'Name <email>'",
        action="append",
        help="SBOM author in 'Name <email>' format (may be given multiple times)",
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


# Strip the per-component reference (e.g. "components[pkg:deb/...]") so that
# identical findings across many components collapse into one summary line.
_FINDING_REF_RE = re.compile(r"\[[^\]]*\]")


def _summarize_findings(findings: list[str]) -> list[tuple[str, int]]:
    """Group findings by message with the component reference stripped, most common first."""
    counts = Counter(_FINDING_REF_RE.sub("[...]", f) for f in findings)
    return counts.most_common()


class _LevelFormatter(logging.Formatter):
    """Plain "%(message)s" for INFO, "%(levelname)-8s %(message)s" otherwise."""

    _plain = logging.Formatter("%(message)s")
    _decorated = logging.Formatter("%(levelname)-8s %(message)s")

    def format(self, record: logging.LogRecord) -> str:
        formatter = self._plain if record.levelno == logging.INFO else self._decorated
        return formatter.format(record)


def main(argv: list[str] | None = None) -> None:
    args = _build_parser().parse_args(argv)
    perf.enabled = args.performance_metrics

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_LevelFormatter())
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        handlers=[handler],
    )

    # ── resolve pipeline components ───────────────────────────────────────────
    try:
        system    = registry.get_system(args.system)
        product_type = args.product_type or system.default_product_type
        # Forward all parsed args as kwargs; registry filters to accepted params.
        formatter = registry.get_formatter(
            args.schema,
            args.spec_version,
            distro=getattr(args, "distro", None),
            product_name=args.product_name,
            product_version=args.product_version,
            product_type=product_type,
            product_supplier=args.product_supplier,
            product_supplier_url=args.product_supplier_url or [],
            product_purl=args.product_purl,
            authors=args.author or [],
        )
        validator = registry.get_validator(args.schema, args.spec_version)
    except ValueError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        sys.exit(1)

    collector = system.make_collector(args)
    enrichers = system.make_enrichers(args)

    # ── run pipeline (schema validation is always included and fatal) ─────────
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
    with perf.timed("write-output"):
        Path(output).write_text(
            json.dumps(bom, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    # ── BSI TR-03183-2 compliance report (advisory, non-fatal) ────────────────
    if args.bsi_tr_compliant:
        with perf.timed("validate:bsi-tr-03183"):
            findings = BsiTr03183Validator().validate(bom)
        if findings:
            report_path = Path(output).with_suffix(".bsi-report.txt")
            report_path.write_text("\n".join(findings) + "\n", encoding="utf-8")

            print(
                f"BSI TR-03183-2 compliance: {len(findings)} finding(s) "
                f"(full list written to {report_path}):",
                file=sys.stderr,
            )
            for message, count in _summarize_findings(findings):
                print(f"  [{count:>4}x] {message}", file=sys.stderr)
        else:
            print("BSI TR-03183-2 compliance: no findings", file=sys.stderr)

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

    if args.performance_metrics:
        perf.report()


if __name__ == "__main__":
    main()
