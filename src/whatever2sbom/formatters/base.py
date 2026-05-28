from abc import ABC, abstractmethod

from whatever2sbom.models import PackageRecord


class Formatter(ABC):
    schema_name: str = ""
    spec_version: str = ""
    output_extension: str = "json"

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def format(self, packages: list[PackageRecord]) -> dict: ...
