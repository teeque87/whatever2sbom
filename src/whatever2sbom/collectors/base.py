from abc import ABC, abstractmethod

from whatever2sbom.models import PackageRecord


class Collector(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def collect(self) -> list[PackageRecord]: ...
