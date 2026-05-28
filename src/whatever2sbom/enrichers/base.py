from abc import ABC, abstractmethod

from whatever2sbom.models import PackageRecord


class Enricher(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def enrich(self, packages: list[PackageRecord]) -> list[PackageRecord]: ...
