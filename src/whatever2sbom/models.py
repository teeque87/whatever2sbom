from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PackageRecord:
    """Uniform representation of a package from any source."""

    # ── identity ──────────────────────────────────────────────────────────────
    name: str
    version: str
    architecture: Optional[str] = None

    # ── classification (drives CycloneDX type / scope) ────────────────────────
    section: Optional[str] = None
    priority: Optional[str] = None
    essential: Optional[str] = None

    # ── provenance ────────────────────────────────────────────────────────────
    source: Optional[str] = None       # source package name
    origin: Optional[str] = None       # repository origin (e.g. Ubuntu)
    maintainer: Optional[str] = None   # "Name <email>" — maps to supplier + contact

    # ── references ────────────────────────────────────────────────────────────
    homepage: Optional[str] = None
    bugs: Optional[str] = None

    # ── dependency graph ──────────────────────────────────────────────────────
    depends: Optional[str] = None
    pre_depends: Optional[str] = None
    provides: Optional[str] = None     # virtual package names this pkg satisfies

    # ── content ───────────────────────────────────────────────────────────────
    description: Optional[str] = None

    # ── size ──────────────────────────────────────────────────────────────────
    installed_size: Optional[str] = None   # KiB on disk
    size: Optional[str] = None             # download size in bytes

    # ── hashes (sha1 / sha512 come from apt-cache enrichment) ─────────────────
    md5sum: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    sha512: Optional[str] = None

    # ── package metadata ──────────────────────────────────────────────────────
    filename: Optional[str] = None     # pool-relative .deb path
    multi_arch: Optional[str] = None

    # ── enriched fields ───────────────────────────────────────────────────────
    licenses: list[str] = field(default_factory=list)
