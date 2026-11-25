"""
Merger abstraction: combine two SBOM documents of the same schema family.

A merger is schema-family-aware, not pinned to one spec version: `detect`
recognises a document from its shape (e.g. CycloneDX's `bomFormat`) and
`spec_version_of` reads the concrete version from the document, so the CLI can
pick the matching validator. New schema families (SPDX, …) register their own
Merger alongside the CycloneDX one, mirroring how formatters/validators are
registered.

The contract is deliberately narrow: `merge(main, incoming)` returns a
`MergeResult` carrying the merged document and a `MergeReport` describing what
happened. The document is the single source of truth; the report is a byproduct
the CLI prints — it is never embedded in the SBOM.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum


class SbomMergeError(Exception):
    """Raised when two SBOMs cannot be merged: schema mismatch, a bom-ref
    collision that the chosen policy refuses to resolve, or structurally
    invalid input."""


class CollisionPolicy(str, Enum):
    """What to do when an incoming component's bom-ref already exists in main.

    AUTO  - components that are the same artifact (equal purl, or equal
            type/name/version) are deduplicated, keeping main's; a genuinely
            different component that merely happens to share a ref is renamed
            to a unique ref, and every edge referring to it is rewritten.
    ERROR - abort on the first colliding ref that is not an exact duplicate.
    """

    AUTO = "auto"
    ERROR = "error"


class MergeMode(str, Enum):
    """How the incoming BOM's described product (metadata.component) is handled.

    FLAT         - the incoming product wrapper node is NOT kept. Its real
                   components are merged into main's flat component list, and
                   the wrapper's own dependency edges are re-parented onto
                   main's root, so the full dependency graph is retained
                   without the wrapper node itself.
    HIERARCHICAL - the incoming product node is kept as a component and attached
                   under main's root, so the incoming BOM survives as a labelled
                   sub-assembly (everything hangs under it).
    """

    FLAT = "flat"
    HIERARCHICAL = "hierarchical"


@dataclass
class MergeReport:
    """A human-readable account of what a merge did, printed by the CLI."""

    incoming_root_ref: str | None = None
    components_added: int = 0
    components_deduplicated: int = 0
    renamed_refs: list[tuple[str, str]] = field(default_factory=list)
    dependency_edges_added: int = 0


@dataclass
class MergeResult:
    document: dict
    report: MergeReport


class Merger(ABC):
    # The schema family this merger produces/validates against. The concrete
    # spec version is not fixed here — it is read from the document itself via
    # `spec_version_of`, so one merger covers every version of its family.
    schema_name: str = ""

    @property
    @abstractmethod
    def name(self) -> str: ...

    @classmethod
    @abstractmethod
    def detect(cls, document: dict) -> bool:
        """True if this merger recognises `document` as its schema family."""

    @classmethod
    @abstractmethod
    def spec_version_of(cls, document: dict) -> str:
        """Read the concrete spec version from `document`.

        Raises SbomMergeError if it cannot be determined, so the caller never
        reaches validation with an unknown version.
        """

    @abstractmethod
    def merge(self, main: dict, incoming: dict) -> MergeResult:
        """Merge `incoming` into `main`.

        `main` keeps all of its metadata; `incoming`'s components are flattened
        into the result with their dependency relationships preserved. Neither
        input is mutated.
        """
