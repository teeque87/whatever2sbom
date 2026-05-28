import re
import uuid
from datetime import datetime, timezone

import whatever2sbom
from whatever2sbom._os import get_os_info
from whatever2sbom.formatters.base import Formatter
from whatever2sbom.models import PackageRecord


_LIBRARY_SECTIONS = frozenset({
    "libs", "libdevel", "python", "perl", "ruby",
    "java", "javascript", "lisp", "ocaml", "haskell",
})
_FIRMWARE_SECTIONS = frozenset({"firmware"})
_OS_SECTIONS = frozenset({"kernel"})


# ── dep-string helpers ────────────────────────────────────────────────────────

def _normalize_dep_name(token: str) -> str:
    """Strip version constraints, arch filters, arch qualifiers from one token."""
    token = re.sub(r"\(.*?\)", "", token)   # (>= 1.2)
    token = re.sub(r"\[.*?\]", "", token)   # [amd64 i386]
    token = token.split(":")[0]             # libc6:amd64 → libc6
    return token.strip()


def _build_provides_map(
    packages: list[PackageRecord],
    name_to_ref: dict[str, str],
) -> dict[str, str]:
    """Return virtual_name → bom_ref from all Provides declarations."""
    provides_map: dict[str, str] = {}
    for pkg in packages:
        if not pkg.provides:
            continue
        bom_ref = name_to_ref.get(pkg.name, "")
        if not bom_ref:
            continue
        for entry in pkg.provides.split(","):
            virtual = _normalize_dep_name(entry)
            if virtual and virtual not in provides_map:
                provides_map[virtual] = bom_ref
    return provides_map


def _resolve_deps(
    dep_string: str,
    name_to_ref: dict[str, str],
    provides_map: dict[str, str],
) -> list[str]:
    """
    Parse a Depends/Pre-Depends field value and return resolved bom-refs.

    - Comma-separated groups are independent deps (all collected).
    - Pipe-separated alternatives: first installed one wins.
    - Virtual packages resolved via provides_map.
    """
    resolved: list[str] = []
    for group in dep_string.split(","):
        group = group.strip()
        if not group:
            continue
        for alt in group.split("|"):
            name = _normalize_dep_name(alt)
            if not name:
                continue
            ref = name_to_ref.get(name) or provides_map.get(name)
            if ref:
                resolved.append(ref)
                break   # first satisfied alternative
    return resolved


# ── component field builders ──────────────────────────────────────────────────

def _build_purl(pkg: PackageRecord, distro: str) -> str:
    purl = f"pkg:deb/{distro}/{pkg.name}@{pkg.version}"
    if pkg.architecture and pkg.architecture != "all":
        purl += f"?arch={pkg.architecture}"
    return purl


def _map_type(pkg: PackageRecord) -> str:
    section = (pkg.section or "").lower().split("/")[-1]
    if (pkg.essential or "").lower() == "yes":
        return "application"
    if section in _LIBRARY_SECTIONS:
        return "library"
    if section in _FIRMWARE_SECTIONS:
        return "firmware"
    if section in _OS_SECTIONS:
        return "operating-system"
    return "library"


def _map_scope(pkg: PackageRecord) -> str:
    priority = (pkg.priority or "").lower()
    if (pkg.essential or "").lower() == "yes" or priority in ("required", "important"):
        return "required"
    return "optional"


def _build_supplier(maintainer: str | None) -> dict | None:
    if not maintainer:
        return None
    m = re.match(r"^(.*?)\s*<([^>]+)>", maintainer.strip())
    if m:
        name, email = m.group(1).strip(), m.group(2).strip()
        return {"name": name, "contact": [{"name": name, "email": email}]}
    return {"name": maintainer.strip()}


def _build_hashes(pkg: PackageRecord) -> list[dict]:
    mapping = [
        ("sha256", "SHA-256"),
        ("sha512", "SHA-512"),
        ("sha1",   "SHA-1"),
        ("md5sum", "MD5"),
    ]
    return [
        {"alg": alg, "content": getattr(pkg, field)}
        for field, alg in mapping
        if getattr(pkg, field, None)
    ]


def _build_licenses(pkg: PackageRecord) -> list[dict] | None:
    if not pkg.licenses:
        return None
    return [{"license": {"name": lic}} for lic in pkg.licenses]


def _build_ext_refs(pkg: PackageRecord) -> list[dict]:
    refs: list[dict] = []
    if pkg.homepage:
        refs.append({"type": "website", "url": pkg.homepage})
    if pkg.bugs:
        refs.append({"type": "issue-tracker", "url": pkg.bugs})
    if pkg.filename:
        refs.append({"type": "distribution", "url": pkg.filename})
    return refs


def _build_properties(pkg: PackageRecord) -> list[dict]:
    prop_map: list[tuple[str, str]] = [
        ("section",        "dpkg:section"),
        ("priority",       "dpkg:priority"),
        ("installed_size", "dpkg:installed-size"),
        ("size",           "dpkg:download-size"),
        ("source",         "dpkg:source"),
        ("origin",         "dpkg:origin"),
        ("multi_arch",     "dpkg:multi-arch"),
    ]
    return [
        {"name": prop_name, "value": str(getattr(pkg, field))}
        for field, prop_name in prop_map
        if getattr(pkg, field, None)
    ]


# ── formatter ─────────────────────────────────────────────────────────────────

class CycloneDXFormatter(Formatter):
    """Produce a CycloneDX 1.6 BOM from a list of PackageRecords."""

    schema_name      = "cyclonedx"
    spec_version     = "1.6"
    output_extension = "cdx.json"
    name             = f"{schema_name}-{spec_version}"

    def __init__(
        self,
        distro: str | None = None,
        product_name: str | None = None,
        product_version: str | None = None,
        product_type: str = "firmware",
        product_supplier: str | None = None,
        product_supplier_url: list[str] | None = None,
        product_purl: str | None = None,
        authors: list[str] | None = None,
    ) -> None:
        self._distro              = distro
        self._product_name        = product_name
        self._product_version     = product_version
        self._product_type        = product_type
        self._product_supplier    = product_supplier
        self._product_supplier_url = product_supplier_url or []
        self._product_purl        = product_purl
        self._authors             = authors or []

    def format(self, packages: list[PackageRecord]) -> dict:
        os_info = get_os_info()
        distro = self._distro or os_info.get("id", "debian")

        name_to_ref: dict[str, str] = {
            pkg.name: _build_purl(pkg, distro)
            for pkg in packages
        }
        provides_map = _build_provides_map(packages, name_to_ref)

        components = [self._build_component(pkg, distro) for pkg in packages]
        dependencies = self._build_dependencies(packages, name_to_ref, provides_map)
        metadata = self._build_metadata(os_info, distro, components)

        # When a product is defined it becomes the root of the dependency tree.
        if self._product_purl:
            pkg_refs = [_build_purl(p, distro) for p in packages]
            dependencies.insert(0, {"ref": self._product_purl, "dependsOn": pkg_refs})

        return {
            "bomFormat":    "CycloneDX",
            "specVersion":  self.spec_version,
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version":      1,
            "metadata":     metadata,
            "components":   components,
            "dependencies": dependencies,
        }

    # ── private helpers ───────────────────────────────────────────────────────

    def _build_component(self, pkg: PackageRecord, distro: str) -> dict:
        bom_ref = _build_purl(pkg, distro)
        component: dict = {
            "type":    _map_type(pkg),
            "bom-ref": bom_ref,
            "name":    pkg.name,
            "version": pkg.version,
            "purl":    bom_ref,
            "scope":   _map_scope(pkg),
        }

        if pkg.description:
            component["description"] = pkg.description

        supplier = _build_supplier(pkg.maintainer)
        if supplier:
            component["supplier"] = supplier

        licenses = _build_licenses(pkg)
        if licenses:
            component["licenses"] = licenses

        hashes = _build_hashes(pkg)
        if hashes:
            component["hashes"] = hashes

        ext_refs = _build_ext_refs(pkg)
        if ext_refs:
            component["externalReferences"] = ext_refs

        props = _build_properties(pkg)
        if props:
            component["properties"] = props

        return component

    def _build_dependencies(
        self,
        packages: list[PackageRecord],
        name_to_ref: dict[str, str],
        provides_map: dict[str, str],
    ) -> list[dict]:
        deps: list[dict] = []
        for pkg in packages:
            direct: list[str] = []
            seen: set[str] = set()
            for field in ("pre_depends", "depends"):
                val = getattr(pkg, field) or ""
                if not val:
                    continue
                for ref in _resolve_deps(val, name_to_ref, provides_map):
                    if ref not in seen and ref != name_to_ref.get(pkg.name):
                        seen.add(ref)
                        direct.append(ref)
            deps.append({"ref": name_to_ref[pkg.name], "dependsOn": direct})
        return deps

    def _build_metadata(
        self, os_info: dict[str, str], distro: str, components: list[dict]
    ) -> dict:
        hash_coverage    = sum(1 for c in components if c.get("hashes"))
        license_coverage = sum(1 for c in components if c.get("licenses"))
        total = len(components)

        metadata: dict = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [{
                    "type":    "application",
                    "name":    whatever2sbom.__title__,
                    "version": whatever2sbom.__version__,
                }]
            },
            "component": self._build_metadata_component(os_info, distro),
            "properties": [
                {"name": "sbom:total-components",     "value": str(total)},
                {"name": "sbom:hash-coverage",        "value": str(hash_coverage)},
                {"name": "sbom:hash-coverage-pct",    "value": f"{hash_coverage / total * 100:.1f}%" if total else "0%"},
                {"name": "sbom:license-coverage",     "value": str(license_coverage)},
                {"name": "sbom:license-coverage-pct", "value": f"{license_coverage / total * 100:.1f}%" if total else "0%"},
            ],
        }

        authors = self._build_authors()
        if authors:
            metadata["authors"] = authors

        return metadata

    def _build_metadata_component(self, os_info: dict[str, str], distro: str) -> dict:
        """Return the metadata.component — product if specified, else OS fallback."""
        if self._product_name:
            comp: dict = {
                "type":    self._product_type,
                "bom-ref": self._product_purl or f"product:{self._product_name}",
                "name":    self._product_name,
            }
            if self._product_version:
                comp["version"] = self._product_version
            if self._product_purl:
                comp["purl"] = self._product_purl
            if self._product_supplier:
                supplier: dict = {"name": self._product_supplier}
                if self._product_supplier_url:
                    supplier["url"] = self._product_supplier_url
                comp["supplier"] = supplier
            return comp

        # Fallback: describe the OS that was scanned
        os_comp: dict = {
            "type":    "operating-system",
            "bom-ref": "os-component",
            "name":    os_info.get("id", distro),
        }
        if os_info.get("version_id"):
            os_comp["version"] = os_info["version_id"]
        if os_info.get("pretty_name"):
            os_comp["description"] = os_info["pretty_name"]
        if os_info.get("home_url"):
            os_comp["externalReferences"] = [
                {"type": "website", "url": os_info["home_url"]}
            ]
        return os_comp

    def _build_authors(self) -> list[dict]:
        """Parse --author 'Name <email>' strings into CycloneDX author objects."""
        result: list[dict] = []
        for entry in self._authors:
            m = re.match(r"^(.*?)\s*<([^>]+)>", entry.strip())
            if m:
                result.append({"name": m.group(1).strip(), "email": m.group(2).strip()})
            else:
                result.append({"name": entry.strip()})
        return result
