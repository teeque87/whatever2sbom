from abc import ABC, abstractmethod
from typing import TypedDict

from whatever2sbom.models import PackageRecord


class CoverageStats(TypedDict):
    """The hash/license coverage summary every formatter must return.

    Percentages are over deployable artifacts only (logical/source-only
    components have no file/hash/licence by nature); `total` counts every
    component in the document.
    """
    total: int
    hash_coverage: int
    hash_coverage_pct: str
    license_coverage: int
    license_coverage_pct: str


class Formatter(ABC):
    schema_name: str = ""
    spec_version: str = ""
    output_extension: str = "json"

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def format(self, packages: list[PackageRecord]) -> dict: ...

    @abstractmethod
    def coverage_stats(self, bom: dict) -> CoverageStats:
        """Return the coverage summary the CLI prints after a run.

        Abstract so every formatter supplies it against its own document shape
        (a CycloneDX formatter counts `components`, an SPDX one `packages`) and
        a new formatter can't silently forget to. Computed on demand, not
        embedded in the SBOM.
        """
        ...
