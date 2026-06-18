from dataclasses import dataclass, field
from typing import Optional


# Property name set on synthetic dpkg "source" pseudo-components (see
# DpkgCollector._build_pseudo_sources). It marks a component that represents a
# *source* package with no installed binary of the same name, added only to
# carry the matchable arch=source coordinate. The formatter excludes these from
# hash/license coverage, and the BSI validator checks them with the relaxed
# logical-component rules (they are not deployable artifacts).
SOURCE_PSEUDO_COMPONENT_PROPERTY = "dpkg:source-pseudo-component"


@dataclass
class PackageRecord:
    """Uniform representation of a package from any source."""

    # identity
    name: str
    version: str
    architecture: Optional[str] = None

    # classification (drives CycloneDX type / scope)
    section: Optional[str] = None
    priority: Optional[str] = None
    essential: Optional[str] = None

    # provenance
    source: Optional[str] = None        # raw dpkg ${Source} field (may be "name (version)" or empty)
    source_name: Optional[str] = None   # resolved source package name (${source:Package})
    source_version: Optional[str] = None  # resolved source version incl. epoch (${source:Version})
    origin: Optional[str] = None       # repository origin (e.g. Ubuntu)
    maintainer: Optional[str] = None   # "Name <email>" — primary supplier + contact
    original_maintainer: Optional[str] = None  # Debian Original-Maintainer (pre-Ubuntu rewrite)

    # references
    homepage: Optional[str] = None
    bugs: Optional[str] = None

    # dependency graph
    depends: Optional[str] = None
    pre_depends: Optional[str] = None
    provides: Optional[str] = None     # virtual package names this pkg satisfies

    # content
    description: Optional[str] = None

    # size
    installed_size: Optional[str] = None   # KiB on disk
    size: Optional[str] = None             # download size in bytes

    # hashes (sha1 / sha512 come from apt-cache enrichment)
    md5sum: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    sha512: Optional[str] = None

    # package metadata
    filename: Optional[str] = None     # pool-relative .deb path
    multi_arch: Optional[str] = None

    # enriched fields
    licenses: list[str] = field(default_factory=list)
    copyright: Optional[str] = None     # copyright notice from DEP-5 copyright file

    # Package-URLs, filled by the collector for its ecosystem (formatters emit
    # these verbatim and never construct PURLs themselves):
    #   purl    — the matchable coordinate a vuln scanner keys on (for deb: the
    #             source package + arch=source).
    #   bom_ref — a unique node id for the dependency graph (for deb: the per-
    #             binary coordinate incl. arch).
    purl: Optional[str] = None
    bom_ref: Optional[str] = None

    # output mapping (computed by the collector, emitted verbatim)
    # Ecosystem-specific classification/parsing rules live in the collector, so
    # formatters stay generic across ecosystems (deb, pip, npm, ...).
    component_type: str = "library"   # CycloneDX component "type"
    scope: str = "required"           # CycloneDX component "scope"
    dependency_refs: list[str] = field(default_factory=list)  # resolved bom-refs of direct deps

    # Component "authors" per CycloneDX 1.6: the person(s) who wrote the
    # software, as "Name <email>" strings. Only set when the ecosystem
    # provides genuine upstream-author metadata (e.g. npm "author"/
    # "contributors", PyPI "Author"); dpkg's Maintainer/Original-Maintainer
    # describe packaging, not authorship, so dpkg leaves this empty.
    authors: list[str] = field(default_factory=list)

    # Additional "Name <email>" contacts for the CycloneDX "supplier" entity,
    # alongside `maintainer` (e.g. dpkg's Original-Maintainer, kept as a
    # secondary packaging contact when it differs from Maintainer).
    supplier_contacts: list[str] = field(default_factory=list)

    # BSI TR-03183-2 §5.2.2 "nature of the component" properties. None means
    # "not determined for this ecosystem" and the property is omitted.
    bsi_executable: Optional[str] = None   # "executable" | "non-executable"
    bsi_archive: Optional[str] = None      # "archive" | "non-archive"
    bsi_structured: Optional[str] = None   # "structured" | "unstructured"

    # Ecosystem-specific (name, value) properties passed through verbatim,
    # e.g. ("dpkg:section", "libs").
    extra_properties: list[tuple[str, str]] = field(default_factory=list)
