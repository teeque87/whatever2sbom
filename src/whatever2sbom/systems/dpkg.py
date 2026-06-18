from __future__ import annotations

import argparse

from whatever2sbom.collectors.dpkg import DpkgCollector
from whatever2sbom.enrichers.apt_cache import AptCacheEnricher
from whatever2sbom.enrichers.copyright import CopyrightEnricher
from whatever2sbom.systems.base import SystemPlugin

_EXCLUDE_HELP = (
    "Exclude an installed package from the SBOM. Either an exact package name "
    "or a glob (*, ?, [...]), e.g. 'linux-image-*' or '*-dbg'. Repeatable; "
    "merged with --exclude-file."
)
_EXCLUDE_FILE_HELP = (
    "File of packages to exclude, one name or glob per line. Blank lines and "
    "'#' comments are ignored. Merged with any --exclude values."
)


class DpkgSystem(SystemPlugin):
    """Debian/Ubuntu installed packages via dpkg-query + apt-cache."""

    name = "dpkg"
    description = "Debian/Ubuntu system packages (dpkg-query + apt-cache enrichment)"
    scans_host_os = True

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        grp = parser.add_argument_group("dpkg system options")
        grp.add_argument(
            "--distro",
            metavar="ID",
            default=None,
            help="Override the OS distro identifier used in package PURLs (e.g. ubuntu)",
        )
        grp.add_argument(
            "--no-apt-cache",
            action="store_true",
            help="Skip apt-cache hash/filename enrichment",
        )
        grp.add_argument(
            "--no-licenses",
            action="store_true",
            help="Skip license extraction from /usr/share/doc/<pkg>/copyright",
        )
        grp.add_argument(
            "--exclude",
            metavar="PATTERN",
            action="append",
            default=None,
            help=_EXCLUDE_HELP,
        )
        grp.add_argument(
            "--exclude-file",
            metavar="FILE",
            default=None,
            help=_EXCLUDE_FILE_HELP,
        )

    def make_collector(self, args: argparse.Namespace) -> DpkgCollector:
        return DpkgCollector(
            distro=getattr(args, "distro", None),
            exclude=getattr(args, "exclude", None),
            exclude_file=getattr(args, "exclude_file", None),
        )

    def make_enrichers(self, args: argparse.Namespace) -> list:
        enrichers = []
        if not getattr(args, "no_apt_cache", False):
            enrichers.append(AptCacheEnricher())
        if not getattr(args, "no_licenses", False):
            enrichers.append(CopyrightEnricher())
        return enrichers
