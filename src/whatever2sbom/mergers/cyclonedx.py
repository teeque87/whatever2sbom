"""
CycloneDX merger: flatten an incoming CycloneDX BOM into a base ("main") BOM.

Strategy
--------
main keeps all of its own metadata verbatim (serialNumber, metadata.component,
tools, …). Only three sections grow: `components`, `dependencies`, and
`compositions`.

The incoming BOM's `metadata.component` (its dependency-tree root) is *promoted*
into the flat `components` list so its whole subtree survives the flatten, then
attached under main's root so nothing is orphaned. Every bom-ref the incoming
BOM uses is run through a rename map, and that map is applied to the dependency
and composition edges too, so the graph stays internally consistent whether a
ref was kept, deduplicated, or renamed on collision.
"""

from __future__ import annotations

import copy
import logging

from whatever2sbom.mergers.base import (
    CollisionPolicy,
    MergeMode,
    MergeReport,
    MergeResult,
    Merger,
    SbomMergeError,
)

logger = logging.getLogger(__name__)

# Suffix appended to an incoming bom-ref that collides with a different main
# component (see CollisionPolicy.AUTO).
_RENAME_SUFFIX = "#merged"


class CycloneDXMerger(Merger):
    schema_name = "cyclonedx"

    def __init__(
        self,
        policy: CollisionPolicy = CollisionPolicy.AUTO,
        mode: MergeMode = MergeMode.FLAT,
    ) -> None:
        self._policy = policy
        self._mode = mode

    @property
    def name(self) -> str:
        return "cyclonedx-merge"

    @classmethod
    def detect(cls, document: dict) -> bool:
        return document.get("bomFormat") == "CycloneDX"

    @classmethod
    def spec_version_of(cls, document: dict) -> str:
        version = document.get("specVersion")
        if not version:
            raise SbomMergeError("CycloneDX document has no specVersion")
        return str(version)

    def merge(self, main: dict, incoming: dict) -> MergeResult:
        merged = copy.deepcopy(main)
        report = MergeReport()

        components = merged.setdefault("components", [])
        main_by_ref = self._index_refs(merged)
        taken_refs = set(main_by_ref)
        main_root_ref = self._root_ref(merged)

        incoming_root_ref = self._root_ref(incoming)
        report.incoming_root_ref = incoming_root_ref

        # The incoming product wrapper (metadata.component) is handled per mode;
        # `dropped` holds refs that must not surface as edges (a wrapper that is
        # discarded with nowhere to re-parent onto).
        flatten, ref_map, dropped = self._plan_root(
            incoming, incoming_root_ref, main_root_ref
        )
        flatten.extend(incoming.get("components") or [])

        self._add_components(flatten, components, main_by_ref, taken_refs, ref_map, report)
        self._merge_dependencies(
            merged, incoming, ref_map, dropped, main_root_ref, incoming_root_ref, report
        )
        self._merge_compositions(merged, incoming, ref_map, dropped)

        return MergeResult(document=merged, report=report)

    def _plan_root(
        self,
        incoming: dict,
        incoming_root_ref: str | None,
        main_root_ref: str | None,
    ) -> tuple[list[dict], dict[str, str], set[str]]:
        """Decide what happens to the incoming product wrapper.

        Returns the list of extra components to flatten (the wrapper itself,
        only in hierarchical mode), the initial ref rename map, and the set of
        refs to suppress from the dependency graph.
        """
        root = (incoming.get("metadata") or {}).get("component")
        ref_map: dict[str, str] = {}
        dropped: set[str] = set()

        if self._mode is MergeMode.HIERARCHICAL and root is not None:
            # Keep the wrapper as a component; it is attached under main's root
            # later. It flows through collision handling like any component.
            return [copy.deepcopy(root)], ref_map, dropped

        # FLAT: the wrapper node is not kept. Re-parent its dependency edges
        # onto main's root so the graph stays whole; if there is no main root to
        # re-parent onto, the wrapper's edges are simply dropped.
        if incoming_root_ref:
            if main_root_ref:
                ref_map[incoming_root_ref] = main_root_ref
            else:
                dropped.add(incoming_root_ref)
        return [], ref_map, dropped

    # component merge

    def _add_components(
        self,
        incoming_components: list[dict],
        components: list[dict],
        main_by_ref: dict[str, dict],
        taken_refs: set[str],
        ref_map: dict[str, str],
        report: MergeReport,
    ) -> None:
        """Append incoming components to `components`, resolving collisions and
        recording old-ref -> new-ref in `ref_map` to apply to the graph."""
        for comp in incoming_components:
            comp = copy.deepcopy(comp)
            old_ref = comp.get("bom-ref", "")

            if old_ref and old_ref in taken_refs:
                existing = main_by_ref.get(old_ref)
                if existing is not None and self._equivalent(existing, comp):
                    # Same artifact already present: keep main's, drop this copy.
                    # Edges to it stay valid because the ref is unchanged.
                    ref_map[old_ref] = old_ref
                    report.components_deduplicated += 1
                    continue
                if self._policy is CollisionPolicy.ERROR:
                    raise SbomMergeError(
                        f"bom-ref collision on {old_ref!r}: the two SBOMs use the "
                        "same ref for different components (re-run with "
                        "--on-collision auto to rename the incoming one)"
                    )
                new_ref = self._unique_ref(old_ref, taken_refs)
                comp["bom-ref"] = new_ref
                ref_map[old_ref] = new_ref
                taken_refs.add(new_ref)
                report.renamed_refs.append((old_ref, new_ref))
            elif old_ref:
                ref_map[old_ref] = old_ref
                taken_refs.add(old_ref)

            components.append(comp)
            report.components_added += 1

    # dependency merge

    def _merge_dependencies(
        self,
        merged: dict,
        incoming: dict,
        ref_map: dict[str, str],
        dropped: set[str],
        main_root_ref: str | None,
        incoming_root_ref: str | None,
        report: MergeReport,
    ) -> None:
        deps = merged.setdefault("dependencies", [])
        by_ref = {dep.get("ref", ""): dep for dep in deps}

        def remap(ref: str) -> str:
            return ref_map.get(ref, ref)

        def edge(ref: str) -> dict:
            entry = by_ref.get(ref)
            if entry is None:
                entry = {"ref": ref, "dependsOn": []}
                by_ref[ref] = entry
                deps.append(entry)
            entry.setdefault("dependsOn", [])
            return entry

        def link(entry: dict, targets: list[str], count: bool) -> None:
            present = set(entry["dependsOn"])
            for target in targets:
                if target and target not in present and target not in dropped:
                    entry["dependsOn"].append(target)
                    present.add(target)
                    if count:
                        report.dependency_edges_added += 1

        for dep in incoming.get("dependencies") or []:
            src = dep.get("ref", "")
            if src in dropped:
                continue
            link(
                edge(remap(src)),
                [remap(t) for t in dep.get("dependsOn", [])],
                count=True,
            )

        # Hierarchical mode: hang the kept incoming wrapper (or, if the incoming
        # BOM had none, its graph roots) under main's root so it isn't orphaned.
        # Flat mode needs no attachment: the wrapper's edges were already
        # re-parented onto main's root via ref_map.
        if self._mode is MergeMode.HIERARCHICAL and main_root_ref:
            link(edge(main_root_ref), self._attachment_refs(incoming, remap), count=False)

    def _attachment_refs(self, incoming: dict, remap) -> list[str]:
        """Incoming refs to hang under main's root (hierarchical mode): the
        kept wrapper if there is one, else the incoming graph's own roots
        (components nothing depends on), so transitive dependencies aren't
        wrongly raised to direct ones."""
        root_ref = self._root_ref(incoming)
        if root_ref:
            return [remap(root_ref)]
        depended = {
            t
            for dep in incoming.get("dependencies") or []
            for t in dep.get("dependsOn", [])
        }
        return [
            remap(ref)
            for comp in incoming.get("components") or []
            if (ref := comp.get("bom-ref")) and ref not in depended
        ]

    # composition merge

    def _merge_compositions(
        self,
        merged: dict,
        incoming: dict,
        ref_map: dict[str, str],
        dropped: set[str],
    ) -> None:
        """Append incoming's completeness aggregates verbatim (ref-mapped, minus
        any dropped wrapper ref) so each subtree keeps its own assertion rather
        than diluting main's."""
        incoming_comps = incoming.get("compositions")
        if not incoming_comps:
            return

        comps = merged.setdefault("compositions", [])
        for comp in incoming_comps:
            comp = copy.deepcopy(comp)
            for key in ("assemblies", "dependencies", "vulnerabilities"):
                if key in comp:
                    comp[key] = [
                        ref_map.get(r, r) for r in comp[key] if r not in dropped
                    ]
            comps.append(comp)

    # helpers

    @staticmethod
    def _root_ref(document: dict) -> str | None:
        """bom-ref of the document's described product (metadata.component)."""
        return (document.get("metadata") or {}).get("component", {}).get("bom-ref")

    @staticmethod
    def _index_refs(document: dict) -> dict[str, dict]:
        """Map every bom-ref in `document` (components + metadata.component) to
        its component object, for collision lookup and equivalence checks."""
        index = {
            ref: comp
            for comp in document.get("components", [])
            if (ref := comp.get("bom-ref"))
        }
        root = (document.get("metadata") or {}).get("component")
        if root and root.get("bom-ref"):
            index.setdefault(root["bom-ref"], root)
        return index

    @staticmethod
    def _equivalent(a: dict, b: dict) -> bool:
        """True if two components denote the same artifact: equal non-empty
        purls, else equal (type, name, version)."""
        pa, pb = a.get("purl"), b.get("purl")
        if pa and pb:
            return pa == pb
        return (a.get("type"), a.get("name"), a.get("version")) == (
            b.get("type"),
            b.get("name"),
            b.get("version"),
        )

    @staticmethod
    def _unique_ref(base: str, taken: set[str]) -> str:
        candidate = f"{base}{_RENAME_SUFFIX}"
        suffix = 2
        while candidate in taken:
            candidate = f"{base}{_RENAME_SUFFIX}-{suffix}"
            suffix += 1
        return candidate
