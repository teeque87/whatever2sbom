from abc import ABC, abstractmethod

from whatever2sbom.models import SOURCE_PSEUDO_COMPONENT_PROPERTY, PackageRecord


def _is_pseudo_source(component: dict) -> bool:
    """True for a synthetic logical "source" component (see PackageRecord).

    These are logical nodes, not deployable artifacts, so they're excluded from
    the hash/license coverage statistics."""
    return any(
        p.get("name") == SOURCE_PSEUDO_COMPONENT_PROPERTY and p.get("value") == "true"
        for p in component.get("properties", [])
    )


class Formatter(ABC):
    schema_name: str = ""
    spec_version: str = ""
    output_extension: str = "json"

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def format(self, packages: list[PackageRecord]) -> dict: ...

    def coverage_stats(self, bom: dict) -> dict:
        """Hash/license coverage for the CLI run summary.

        Part of the formatter interface so every formatter (present and future)
        supplies it. The default reads the CycloneDX `components` array — the
        shared document shape today; a formatter with a different model (e.g.
        SPDX `packages`) overrides this.

        Percentages are over deployable artifacts only: synthetic logical
        "source" components have no file/hash/licence by nature, so counting
        them as "missing" would skew the stats. `total` still counts every
        component. Computed on demand (not embedded in the SBOM) so the
        persisted document stays free of non-standard properties.
        """
        components = bom.get("components", [])
        artifacts = [c for c in components if not _is_pseudo_source(c)]
        artifact_total = len(artifacts)
        hash_coverage    = sum(1 for c in artifacts if c.get("hashes"))
        license_coverage = sum(1 for c in artifacts if c.get("licenses"))

        def pct(n: int) -> str:
            return f"{n / artifact_total * 100:.1f}%" if artifact_total else "0%"

        return {
            "total":                len(components),
            "hash_coverage":        hash_coverage,
            "hash_coverage_pct":    pct(hash_coverage),
            "license_coverage":     license_coverage,
            "license_coverage_pct": pct(license_coverage),
        }
