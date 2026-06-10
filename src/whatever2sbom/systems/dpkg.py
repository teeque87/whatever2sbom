from __future__ import annotations

import argparse

from whatever2sbom.collectors.dpkg import DpkgCollector
from whatever2sbom.enrichers.apt_cache import AptCacheEnricher
from whatever2sbom.enrichers.copyright import CopyrightEnricher
from whatever2sbom.systems.base import SystemPlugin


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

    def make_collector(self, args: argparse.Namespace) -> DpkgCollector:
        return DpkgCollector(distro=getattr(args, "distro", None))

    def make_enrichers(self, args: argparse.Namespace) -> list:
        enrichers = []
        if not getattr(args, "no_apt_cache", False):
            enrichers.append(AptCacheEnricher())
        if not getattr(args, "no_licenses", False):
            enrichers.append(CopyrightEnricher())
        return enrichers
