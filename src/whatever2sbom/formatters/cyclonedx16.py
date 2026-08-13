import re
import uuid
from datetime import datetime, timezone
from pathlib import PurePosixPath

import whatever2sbom
from whatever2sbom.formatters.base import Formatter
from whatever2sbom.models import PackageRecord
from whatever2sbom.util import spdx
from whatever2sbom.util.os_release import get_os_info


_NAME_NORMALIZE_RE = re.compile(r"[-_.]+")


def _normalize_component_name(name: str) -> str:
    """Loosely normalize a component name for comparison (PEP 503-ish:
    lowercase, runs of -_. collapse to '-'). Used to recognize when a scanned
    package *is* the product being described (e.g. scanning a project's own
    venv, which includes the project itself)."""
    return _NAME_NORMALIZE_RE.sub("-", name).lower()


# component field builders

def _parse_name_email(raw: str) -> tuple[str, str | None]:
    """Split "Name <email>" into (name, email | None)."""
    m = re.match(r"^(.*?)\s*<([^>]+)>", raw.strip())
    if m:
        return m.group(1).strip(), m.group(2).strip()
    return raw.strip(), None


def _build_supplier(pkg: PackageRecord) -> dict | None:
    """
    CycloneDX `supplier`: who builds/distributes the component. `maintainer`
    is the primary contact; `supplier_contacts` (e.g. dpkg's
    Original-Maintainer) are additional packaging contacts for the same
    supplier, not separate authors.
    """
    raw_contacts = [c for c in (pkg.maintainer, *pkg.supplier_contacts) if c]
    if not raw_contacts:
        return None

    contacts: list[dict] = []
    seen: set[tuple[str, str | None]] = set()
    for raw in raw_contacts:
        name, email = _parse_name_email(raw)
        if (name, email) in seen:
            continue
        seen.add((name, email))
        contact: dict = {"name": name}
        if email:
            contact["email"] = email
        contacts.append(contact)

    supplier: dict = {"name": contacts[0]["name"]}
    if any("email" in c for c in contacts):
        supplier["contact"] = contacts
    return supplier


def _build_component_authors(pkg: PackageRecord) -> list[dict] | None:
    """
    Component authors per CycloneDX 1.6: the person(s) who wrote the
    component's source code. Only set when the collector populated
    `pkg.authors` with genuine upstream-author metadata (see PackageRecord).
    """
    if not pkg.authors:
        return None
    result: list[dict] = []
    for raw in pkg.authors:
        name, email = _parse_name_email(raw)
        author: dict = {"name": name}
        if email:
            author["email"] = email
        result.append(author)
    return result


# Deprecated SPDX license IDs (e.g. "GPL-2.0+") still resolve to a page on
# spdx.org, so the URL pattern below is valid for every literal id in the
# bundled SPDX list -- no network lookup or separate cache needed.
def _spdx_license_url(license_id: str) -> str:
    return f"https://spdx.org/licenses/{license_id}.html"


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
    """
    Build a CycloneDX licenseChoice from pkg.licenses, preferring SPDX license
    identifiers / expressions per BSI TR-03183-2 §6.1.

    A single license that is itself an SPDX expression (e.g. "MIT OR
    Apache-2.0") is emitted using the dedicated `expression` form, since
    CycloneDX does not allow mixing `expression` with `license` entries.

    Each entry is marked `"acknowledgement": "declared"` per the BSI
    "Original licences" mapping (Table 11) -- these are the licenses as
    declared by the package, not the result of a separate concluded-license
    analysis.
    """
    # Safety net: never emit license *text* that leaked into the license field
    # (a whole LICENSE pasted into a package's metadata). Collectors aim to hand
    # us only identifiers, but this guarantees a valid entry regardless.
    values = [lic for lic in pkg.licenses if not spdx.is_probably_license_text(lic)]
    if not values:
        return None

    classified = [spdx.classify_license(lic) for lic in values]

    if len(classified) == 1 and classified[0]["kind"] == "expression":
        return [{"expression": classified[0]["value"], "acknowledgement": "declared"}]

    result: list[dict] = []
    for c in classified:
        if c["kind"] == "id":
            result.append({"license": {
                "id": c["value"],
                "url": _spdx_license_url(c["value"]),
                "acknowledgement": "declared",
            }})
        else:
            result.append({"license": {"name": c["value"], "acknowledgement": "declared"}})
    return result


def _build_effective_license_property(pkg: PackageRecord) -> dict | None:
    """
    `bsi:component:effectiveLicense` per BSI TR-03183-2 Table 12 (optional):
    the resulting SPDX license expression for the component.

    We have no separate concluded-license analysis, so this is only emitted
    when every declared license is itself SPDX-compliant (id, expression, or
    LicenseRef-*), combined with AND -- the conventional reading of "this
    component is governed by all of these licenses together".
    """
    if not pkg.licenses:
        return None

    classified = [spdx.classify_license(lic) for lic in pkg.licenses]
    if not all(c["compliant"] for c in classified):
        return None

    values = [c["value"] for c in classified]
    expression = values[0] if len(values) == 1 else " AND ".join(f"({v})" for v in values)
    return {"name": "bsi:component:effectiveLicense", "value": expression}


def _build_bsi_properties(pkg: PackageRecord) -> list[dict]:
    """
    Component properties per BSI TR-03183-2 §5.2.2: filename, executable /
    archive / structured, effective license.

    The executable/archive/structured classification is ecosystem-specific
    (e.g. a .deb is itself an `ar` archive carrying control metadata, while an
    installed npm/pip package is a plain unpacked directory) so the collector
    decides those values; here they're only emitted when the collector set
    them.
    """
    props: list[dict] = []
    if pkg.filename:
        props.append({
            "name": "bsi:component:filename",
            "value": PurePosixPath(pkg.filename).name,
        })
    if pkg.bsi_executable:
        props.append({"name": "bsi:component:executable", "value": pkg.bsi_executable})
    if pkg.bsi_archive:
        props.append({"name": "bsi:component:archive", "value": pkg.bsi_archive})
    if pkg.bsi_structured:
        props.append({"name": "bsi:component:structured", "value": pkg.bsi_structured})

    effective_license = _build_effective_license_property(pkg)
    if effective_license:
        props.append(effective_license)

    return props


def _build_ext_refs(pkg: PackageRecord) -> list[dict]:
    refs: list[dict] = []
    if pkg.homepage:
        refs.append({"type": "website", "url": pkg.homepage})
    if pkg.bugs:
        refs.append({"type": "issue-tracker", "url": pkg.bugs})
    return refs


def _build_extra_properties(pkg: PackageRecord) -> list[dict]:
    """Ecosystem-specific properties (e.g. dpkg:section), passed through verbatim."""
    return [{"name": name, "value": value} for name, value in pkg.extra_properties]


# formatter

class CycloneDXFormatter(Formatter):
    """Produce a CycloneDX 1.6 BOM from a list of PackageRecords."""

    schema_name      = "cyclonedx"
    spec_version     = "1.6"
    output_extension = "cdx.json"

    @property
    def name(self) -> str:
        return f"{self.schema_name}-{self.spec_version}"

    def __init__(
        self,
        distro: str | None = None,
        product_name: str | None = None,
        product_version: str | None = None,
        product_type: str = "operating-system",
        product_supplier: str | None = None,
        product_supplier_url: list[str] | None = None,
        product_supplier_email: str | None = None,
        product_purl: str | None = None,
        authors: list[str] | None = None,
        describe_os: bool = True,
    ) -> None:
        self._distro               = distro
        self._product_name         = product_name
        self._product_version      = product_version
        self._product_type         = product_type
        self._product_supplier     = product_supplier
        self._product_supplier_url = product_supplier_url or []
        self._product_supplier_email = product_supplier_email
        self._product_purl         = product_purl
        self._authors              = authors or []
        self._describe_os          = describe_os

    def format(self, packages: list[PackageRecord]) -> dict:
        os_info  = get_os_info()
        distro   = self._distro or os_info.get("id", "debian")

        components   = [self._build_component(pkg) for pkg in packages]
        dependencies = self._build_dependencies(packages)
        metadata     = self._build_metadata(os_info, distro)

        # metadata.component is always the single root of the dependency tree.
        # If one of the scanned packages *is* the product (e.g. scanning a
        # project's own venv, which includes the project itself), it must not
        # be listed as a dependency of itself -- and the root's *direct*
        # dependencies are that package's own resolved dependency_refs (its
        # Requires-Dist), not every package in the environment. Otherwise
        # (e.g. scanning a dpkg system as a whole), every package is a direct
        # part of what was scanned.
        root_ref = self._root_bom_ref()
        pkg_refs = [
            p.bom_ref or "" for p in packages if not self._is_product_component(p)
        ]
        product_pkg = next((p for p in packages if self._is_product_component(p)), None)
        root_deps = product_pkg.dependency_refs if product_pkg is not None else pkg_refs
        if root_ref is not None:
            dependencies.insert(0, {"ref": root_ref, "dependsOn": root_deps})

        return {
            "bomFormat":    "CycloneDX",
            "specVersion":  self.spec_version,
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version":      1,
            "metadata":     metadata,
            "components":   components,
            "dependencies": dependencies,
            "compositions": self._build_compositions(root_ref, pkg_refs),
        }

    def _build_compositions(self, root_ref: str | None, pkg_refs: list[str]) -> list[dict]:
        """
        Indicate dependency-completeness per BSI TR-03183-2 §5.2.2.

        Dependencies not satisfied by an installed package (e.g. unresolved
        virtual packages or alternatives) are silently dropped during
        resolution, so the recorded dependency graph cannot be asserted as
        "complete" — it is explicitly marked "unknown".
        """
        dependencies = [root_ref, *pkg_refs] if root_ref is not None else pkg_refs
        return [{
            "aggregate": "unknown",
            "dependencies": dependencies,
        }]

    def _is_product_component(self, pkg: PackageRecord) -> bool:
        """True if `pkg` is the product itself (--product-name), not a dependency of it."""
        if not self._product_name:
            return False
        return _normalize_component_name(pkg.name) == _normalize_component_name(self._product_name)

    # private helpers

    def _root_bom_ref(self) -> str | None:
        """bom-ref of metadata.component — used as the single root of the dep tree.

        Returns None when metadata.component is omitted (no product
        described and the scanned thing isn't the host OS).
        """
        if self._product_purl:
            return self._product_purl
        if self._product_name:
            return f"product:{self._product_name}"
        if not self._describe_os:
            return None
        return "os-component"

    def _build_component(self, pkg: PackageRecord) -> dict:
        # type/scope/purl/bom_ref are ecosystem facts decided by the collector:
        # bom_ref is the unique per-binary coordinate (keeps the dependency
        # graph intact); purl is the source coordinate scanners key on.
        component: dict = {
            "type":    pkg.component_type,
            "bom-ref": pkg.bom_ref or "",
        }
        # group (e.g. the deb source package) precedes name, per CycloneDX's
        # group/name/version ordering; omitted when the collector left it unset.
        if pkg.group:
            component["group"] = pkg.group
        component["name"]    = pkg.name
        component["version"] = pkg.version
        component["purl"]    = pkg.purl or ""
        component["scope"]   = pkg.scope

        if pkg.description:
            component["description"] = pkg.description

        supplier = _build_supplier(pkg)
        if supplier:
            component["supplier"] = supplier

        authors = _build_component_authors(pkg)
        if authors:
            component["authors"] = authors

        if pkg.copyright:
            component["copyright"] = pkg.copyright

        licenses = _build_licenses(pkg)
        if licenses:
            component["licenses"] = licenses

        hashes = _build_hashes(pkg)
        if hashes:
            component["hashes"] = hashes

        ext_refs = _build_ext_refs(pkg)
        if ext_refs:
            component["externalReferences"] = ext_refs

        props = _build_extra_properties(pkg) + _build_bsi_properties(pkg)
        component["properties"] = props

        return component

    def _build_dependencies(self, packages: list[PackageRecord]) -> list[dict]:
        # Dependency resolution is an ecosystem fact decided by the collector
        # (e.g. parsing dpkg's Depends/Provides syntax); dependency_refs is
        # already a deduped list of resolved bom-refs, emitted verbatim.
        return [
            {"ref": pkg.bom_ref or "", "dependsOn": pkg.dependency_refs}
            for pkg in packages
        ]

    def _build_metadata(self, os_info: dict[str, str], distro: str) -> dict:
        metadata: dict = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [{
                    "type":    "application",
                    "name":    whatever2sbom.__title__,
                    "version": whatever2sbom.__version__,
                }]
            },
        }

        component = self._build_metadata_component(os_info, distro)
        if component is not None:
            metadata["component"] = component

        supplier: dict = {"name": self._product_supplier}
        if self._product_supplier_url:
            supplier["url"] = self._product_supplier_url
        if self._product_supplier_email:
            supplier["contact"] = [{"email": self._product_supplier_email}]
        metadata["supplier"] = supplier

        authors = self._build_authors()
        if authors:
            metadata["authors"] = authors

        return metadata

    def _build_metadata_component(self, os_info: dict[str, str], distro: str) -> dict | None:
        """Return the metadata.component — product if specified, else OS fallback.

        Returns None if neither a product nor the host OS is being described
        (e.g. --system pip without --product-name): metadata.component is
        optional per the CycloneDX schema, and falling back to the host OS
        there would misrepresent a venv as the operating system.
        """
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
                if self._product_supplier_email:
                    supplier["contact"] = [{"email": self._product_supplier_email}]
                comp["supplier"] = supplier
            return comp

        if not self._describe_os:
            return None

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
