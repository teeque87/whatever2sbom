from abc import ABC, abstractmethod


class ValidationError(Exception):
    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__(f"{len(errors)} validation error(s)")


class Validator(ABC):
    schema_name: str = ""
    spec_version: str = ""

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def validate(self, bom: dict) -> list[str]: ...
