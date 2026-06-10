"""
Base class for system plugins.

A system plugin defines one scannable ecosystem (dpkg, pip, npm, …).
It owns:
  - which CLI arguments it needs (added to the shared parser)
  - how to build a Collector from those args
  - how to build the Enricher chain from those args

To add a new ecosystem, subclass SystemPlugin, implement the three abstract
methods, and register an instance via registry.register_system().
"""

from __future__ import annotations

import argparse
from abc import ABC, abstractmethod

from whatever2sbom.collectors.base import Collector
from whatever2sbom.enrichers.base import Enricher


class SystemPlugin(ABC):

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier used with --system (e.g. 'dpkg', 'pip')."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """One-line description shown in --help."""
        ...

    @property
    def default_product_type(self) -> str:
        """CycloneDX component type for metadata.component when --product-name
        is given but --product-type is not. Override for ecosystems where
        "operating-system" doesn't fit (e.g. "application" for a pip
        virtualenv)."""
        return "operating-system"

    @property
    def scans_host_os(self) -> bool:
        """True if the thing being scanned *is* the host operating system, so
        metadata.component can fall back to describing it (from
        /etc/os-release) when --product-name is not given.

        False for systems (e.g. pip, scanning one virtualenv) where the
        scanned thing isn't the host OS -- describing the host OS there would
        be misleading, so metadata.component is omitted instead."""
        return False

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """
        Register system-specific CLI arguments on the shared parser.

        Override to add a dedicated argument group, e.g.:
            grp = parser.add_argument_group(f"{self.name} options")
            grp.add_argument("--distro", ...)
        """

    @abstractmethod
    def make_collector(self, args: argparse.Namespace) -> Collector:
        """Return a configured Collector for this system."""
        ...

    @abstractmethod
    def make_enrichers(self, args: argparse.Namespace) -> list[Enricher]:
        """Return the ordered list of Enrichers for this system."""
        ...
