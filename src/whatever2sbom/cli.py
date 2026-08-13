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
from whatever2sbom import registry
from whatever2sbom.formatters.cyclonedx16 import coverage_stats
from whatever2sbom.pipeline import SbomPipeline
from whatever2sbom.plugins import PluginError, load_plugin, parse_plugin_configs
from whatever2sbom.util import perf
from whatever2sbom.validators.base import ValidationError
from whatever2sbom.validators.bsi_tr03183 import BsiTr03183Validator


def _detect_system(argv: list[str] | None, systems: list[str], default: str) -> str:
    """Pre-parse only --system so the full parser can be built with just the
    selected system's options.

    Lenient by design: a missing or unknown value falls back to `default` here
    and is re-validated (with a proper error message) by the full parser, whose
    --system carries the real `choices`.
    """
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--system")
    try:
        known, _ = pre.parse_known_args(argv)
    except SystemExit:
        return default
    return known.system if known.system in systems else default


def _build_parser(selected_system: str) -> argparse.ArgumentParser:
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

    # global scan / output options
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
            "[experimental, not feature-complete] Additionally validate the SBOM "
            "against the BSI TR-03183-2 v2.1.0 data-field requirements (SPDX "
            "licences, SHA-512 hashes, creator contact info, "
            "executable/archive/structured properties, …). Advisory only."
        ),
    )

    # product metadata (BSI TR-03183)
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
            "(firmware | application | container | device | operating-system | …)  "
            "(default: depends on --system, e.g. operating-system for dpkg, application for pip/npm)"
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
        "--product-supplier-email",
        metavar="EMAIL",
        dest="product_supplier_email",
        help=(
            "Supplier contact e-mail address "
            "(satisfies BSI TR-03183-2 §3.2.2 / §5.2.1 creator contact requirement)"
        ),
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

    # plugins (optional post-processing, run last before validation)
    plug = p.add_argument_group(
        "plugins",
        "Optional post-processing plugins. Each runs last — after formatting, "
        "just before schema validation — so its output is still validated.",
    )
    plug.add_argument(
        "--plugin",
        action="append",
        dest="plugins",
        metavar="NAME",
        help=(
            "Enable a plugin by script name (without .py). May be given multiple "
            "times; plugins run in the order listed. See the Plugins guide."
        ),
    )
    plug.add_argument(
        "--plugin-config",
        action="append",
        dest="plugin_config",
        metavar="NAME:KEY=VALUE",
        help=(
            "Configure a plugin (repeatable). A comma-separated VALUE becomes a "
            "list, e.g. --plugin-config patch-purl:packages=bash,coreutils"
        ),
    )
    plug.add_argument(
        "--plugin-config-file",
        dest="plugin_config_file",
        metavar="FILE",
        help=(
            "JSON file mapping plugin name -> config object. Merged under any "
            "inline --plugin-config values (which win on conflict)."
        ),
    )

    # system-specific options
    # Only the *selected* system's options are registered, so --help stays
    # focused as more ecosystems are added (and per-system flag names can't
    # collide across systems). The other systems are pointed at in the epilog.
    registry.get_system(selected_system).add_arguments(p)

    others = [name for name in systems if name != selected_system]
    if others:
        p.epilog = (
            f"showing options for --system {selected_system}. "
            f"other systems: {', '.join(others)} "
            f"(run `--system <name> --help` to see their options)."
        )

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
    systems = registry.system_names()
    default_system = systems[0] if systems else "dpkg"
    parser = _build_parser(_detect_system(argv, systems, default_system))
    args = parser.parse_args(argv)
    perf.enabled = args.performance_metrics

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_LevelFormatter())
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        handlers=[handler],
    )

    # resolve pipeline components
    try:
        system    = registry.get_system(args.system)

        # Systems that don't scan the host OS (e.g. pip, scanning a venv)
        # have no fallback subject for metadata.component, so --product-name
        # must be given explicitly -- unlike dpkg, where the host OS itself
        # serves as the default subject.
        if not system.scans_host_os and not args.product_name:
            parser.error(
                f"--product-name is required for --system {args.system} "
                "(it cannot fall back to describing the host OS)"
            )

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
            product_supplier_email=args.product_supplier_email,
            product_purl=args.product_purl,
            authors=args.author or [],
            describe_os=system.scans_host_os,
        )
        validator = registry.get_validator(args.schema, args.spec_version)
    except ValueError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        sys.exit(1)

    # resolve optional post-processing plugins
    try:
        plugin_configs = parse_plugin_configs(args.plugin_config, args.plugin_config_file)
        plugins = [
            load_plugin(name, plugin_configs.get(name, {}))
            for name in (args.plugins or [])
        ]
    except PluginError as exc:
        print(f"Plugin error: {exc}", file=sys.stderr)
        sys.exit(1)

    collector = system.make_collector(args)
    enrichers = system.make_enrichers(args)

    # run pipeline (schema validation is always included and fatal)
    pipeline = SbomPipeline(
        collector=collector,
        enrichers=enrichers,
        formatter=formatter,
        validators=[validator],
        plugins=plugins,
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

    # write output
    output = args.output or _default_filename(args.schema)
    with perf.timed("write-output"):
        Path(output).write_text(
            json.dumps(bom, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    # BSI TR-03183-2 compliance report (advisory, non-fatal)
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

    # summary
    stats = coverage_stats(bom.get("components", []))

    print(f"SBOM written -> {output}")
    print(f"  system          : {args.system}")
    print(f"  schema          : {args.schema} {args.spec_version}")
    for label, value in (
        ("total components", stats["total"]),
        ("hash coverage",    stats["hash_coverage_pct"]),
        ("license coverage", stats["license_coverage_pct"]),
    ):
        print(f"  {label:<16}: {value}")

    if args.performance_metrics:
        perf.report()


if __name__ == "__main__":
    main()
