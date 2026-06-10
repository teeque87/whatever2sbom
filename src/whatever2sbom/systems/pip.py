from __future__ import annotations

import argparse

from whatever2sbom.collectors.pip import PipCollector
from whatever2sbom.systems.base import SystemPlugin


class PipSystem(SystemPlugin):
    """Python packages installed in a virtualenv (importlib.metadata)."""

    name = "pip"
    description = "Python virtualenv packages (importlib.metadata + Requires-Dist graph)"
    default_product_type = "application"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        grp = parser.add_argument_group("pip system options")
        grp.add_argument(
            "--venv-dir",
            metavar="PATH",
            default=None,
            help=(
                "Path to the virtualenv to scan (default: auto-detect a "
                "directory containing pyvenv.cfg under --project-dir)"
            ),
        )
        grp.add_argument(
            "--project-dir",
            metavar="PATH",
            default=".",
            help=(
                "Project root to search for a virtualenv when --venv-dir is "
                "not given (default: current directory)"
            ),
        )

    def make_collector(self, args: argparse.Namespace) -> PipCollector:
        return PipCollector(venv_dir=args.venv_dir, project_dir=args.project_dir)

    def make_enrichers(self, args: argparse.Namespace) -> list:
        return []
