from __future__ import annotations

import argparse

from whatever2sbom.collectors.npm import NpmCollector
from whatever2sbom.systems.base import SystemPlugin


class NpmSystem(SystemPlugin):
    """Node.js packages resolved from an npm package-lock.json (best-effort
    from the lockfile alone; richer per-package metadata can be added later via
    an enricher reading node_modules/<pkg>/package.json)."""

    name = "npm"
    description = "Node.js npm packages (package-lock.json dependency graph)"
    default_product_type = "application"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        grp = parser.add_argument_group("npm system options")
        grp.add_argument(
            "--lockfile",
            metavar="PATH",
            default=None,
            help=(
                "Path to package-lock.json, or a directory containing it "
                "(default: ./package-lock.json)"
            ),
        )
        grp.add_argument(
            "--exclude-dev-dependencies",
            action="store_true",
            dest="exclude_dev_dependencies",
            help="Omit devDependencies (lockfile entries marked dev / devOptional)",
        )

    def make_collector(self, args: argparse.Namespace) -> NpmCollector:
        return NpmCollector(
            lockfile=getattr(args, "lockfile", None),
            exclude_dev=getattr(args, "exclude_dev_dependencies", False),
        )

    def make_enrichers(self, args: argparse.Namespace) -> list:
        return []
