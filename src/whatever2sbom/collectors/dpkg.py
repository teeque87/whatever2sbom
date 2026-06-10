import logging
import re
import subprocess

from whatever2sbom.collectors.base import Collector
from whatever2sbom.models import PackageRecord
from whatever2sbom.util import purl as _purl
from whatever2sbom.util.os_release import get_os_info

logger = logging.getLogger(__name__)

# CycloneDX type/scope mapping (dpkg ${Section}/${Priority}/${Essential})

_LIBRARY_SECTIONS = frozenset({
    "libs", "libdevel", "python", "perl", "ruby",
    "java", "javascript", "lisp", "ocaml", "haskell",
})
_FIRMWARE_SECTIONS = frozenset({"firmware"})
_OS_SECTIONS = frozenset({"kernel"})


def _map_component_type(pkg: PackageRecord) -> str:
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


# extra (dpkg:*) properties

_EXTRA_PROPERTY_FIELDS: list[tuple[str, str]] = [
    ("section",        "dpkg:section"),
    ("priority",       "dpkg:priority"),
    ("installed_size", "dpkg:installed-size"),
    ("size",           "dpkg:download-size"),
    ("source",         "dpkg:source"),
    ("source_name",    "dpkg:source-name"),
    ("source_version", "dpkg:source-version"),
    ("origin",         "dpkg:origin"),
    ("multi_arch",     "dpkg:multi-arch"),
]


def _build_extra_properties(pkg: PackageRecord) -> list[tuple[str, str]]:
    return [
        (prop_name, str(getattr(pkg, field)))
        for field, prop_name in _EXTRA_PROPERTY_FIELDS
        if getattr(pkg, field, None)
    ]


# dependency graph (Depends/Pre-Depends/Provides)

def _normalize_dep_name(token: str) -> str:
    """Strip version constraints, arch filters, arch qualifiers from one token."""
    token = re.sub(r"\(.*?\)", "", token)   # (>= 1.2)
    token = re.sub(r"\[.*?\]", "", token)   # [amd64 i386]
    token = token.split(":")[0]             # libc6:amd64 -> libc6
    return token.strip()


def _build_provides_map(
    packages: list[PackageRecord],
    name_to_ref: dict[str, str],
) -> dict[str, str]:
    """Return virtual_name -> bom_ref from all Provides declarations."""
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


def _resolve_dependencies(packages: list[PackageRecord]) -> None:
    """Resolve each package's Pre-Depends/Depends into pkg.dependency_refs."""
    name_to_ref = {pkg.name: pkg.bom_ref or "" for pkg in packages}
    provides_map = _build_provides_map(packages, name_to_ref)

    for pkg in packages:
        seen: set[str] = set()
        direct: list[str] = []
        for field in ("pre_depends", "depends"):
            val = getattr(pkg, field) or ""
            if not val:
                continue
            for ref in _resolve_deps(val, name_to_ref, provides_map):
                if ref not in seen and ref != pkg.bom_ref:
                    seen.add(ref)
                    direct.append(ref)
        pkg.dependency_refs = direct

# Fields fetched from dpkg-query.
# status_want / status_status are used only for filtering; they are not stored
# on PackageRecord.  sha1 / sha512 are not available here — they come from the
# AptCacheEnricher.
_FIELDS: dict[str, str] = {
    "package":        "${binary:Package}",
    "version":        "${Version}",
    "architecture":   "${Architecture}",
    "source":         "${Source}",
    # Resolved source identity. ${source:Package}/${source:Version} fall back to
    # the binary name/version when a package has no distinct source, and crucially
    # carry the source version *with epoch* and without binNMU suffixes — which is
    # exactly the coordinate OSV / Ubuntu security data is published against.
    "source_package": "${source:Package}",
    "source_version": "${source:Version}",
    "section":        "${Section}",
    "priority":       "${Priority}",
    "installed_size": "${Installed-Size}",
    "maintainer":     "${Maintainer}",
    "homepage":       "${Homepage}",
    "origin":         "${Origin}",
    "bugs":           "${Bugs}",
    "essential":      "${Essential}",
    "multi_arch":     "${Multi-Arch}",
    "depends":        "${Depends}",
    "pre_depends":    "${Pre-Depends}",
    "provides":       "${Provides}",
    "description":    "${Description}",
    "filename":       "${Filename}",
    "size":           "${Size}",
    "md5sum":         "${MD5sum}",
    "sha256":         "${SHA256}",
    # installation status — used for filtering only
    "status_want":    "${db:Status-Want}",
    "status_status":  "${db:Status-Status}",
}

_RECORD_SEP = "---RECORD_END---"


def _build_format_string() -> str:
    parts = "\n".join(f"{key}={var}" for key, var in _FIELDS.items())
    return parts + f"\n{_RECORD_SEP}\n"


def _parse_record(block: str) -> dict[str, str]:
    record: dict[str, str] = {}
    current_key: str | None = None
    current_lines: list[str] = []

    def _flush() -> None:
        if current_key is not None:
            record[current_key] = "\n".join(current_lines).strip()

    for line in block.splitlines():
        matched = next((k for k in _FIELDS if line.startswith(f"{k}=")), None)
        if matched:
            _flush()
            current_key = matched
            current_lines = [line[len(matched) + 1:]]
        elif current_key is not None:
            current_lines.append(line)

    _flush()
    return record


def _to_record(raw: dict[str, str]) -> PackageRecord:
    def v(key: str) -> str | None:
        val = raw.get(key, "")
        return val if val else None

    # dpkg renders Multi-Arch packages as "name:arch" in ${binary:Package}.
    # Package names never contain a colon, so strip the arch qualifier to get
    # the bare name — the architecture is captured separately (and lands in the
    # PURL `arch=` qualifier). This also keeps dependency-graph keys consistent
    # with _normalize_dep_name in the formatter, which already strips ":arch".
    name = raw["package"].split(":")[0]

    return PackageRecord(
        name=name,
        version=v("version") or "",
        architecture=v("architecture"),
        source=v("source"),
        source_name=v("source_package"),
        source_version=v("source_version"),
        section=v("section"),
        priority=v("priority"),
        installed_size=v("installed_size"),
        maintainer=v("maintainer"),
        homepage=v("homepage"),
        origin=v("origin"),
        bugs=v("bugs"),
        essential=v("essential"),
        multi_arch=v("multi_arch"),
        depends=v("depends"),
        pre_depends=v("pre_depends"),
        provides=v("provides"),
        description=v("description"),
        filename=v("filename"),
        size=v("size"),
        md5sum=v("md5sum"),
        sha256=v("sha256"),
    )


def _resolve_distro(override: str | None, os_info: dict[str, str]) -> tuple[str, str | None]:
    """Return (distro_id, codename), honoring an explicit override."""
    distro = override or os_info.get("id") or "debian"
    codename = os_info.get("version_codename") or None
    return distro, codename


def _fill_purls(pkg: PackageRecord, distro: str, codename: str | None) -> None:
    """Fill the matchable PURL and the unique bom_ref for one package.

    - bom_ref: the per-binary coordinate (name + arch) — unique dep-graph node id.
    - purl:    the source coordinate with arch=source — what vuln scanners match.

    source_name/source_version fall back to the binary name/version for packages
    that have no distinct source.
    """
    pkg.bom_ref = _purl.deb(distro, pkg.name, pkg.version, pkg.architecture or "", codename)

    src_name = pkg.source_name or pkg.name
    src_ver = pkg.source_version or pkg.version
    pkg.purl = _purl.deb(distro, src_name, src_ver, "source", codename)


def _fill_output_mapping(pkg: PackageRecord) -> None:
    """Fill the CycloneDX type/scope/properties for one package.

    A .deb is itself an `ar` archive carrying control metadata (a "structured
    archive"); it is not directly executed, even though it may contain
    executables.
    """
    pkg.component_type = _map_component_type(pkg)
    pkg.scope = _map_scope(pkg)
    pkg.bsi_executable = "non-executable"
    pkg.bsi_archive = "archive"
    pkg.bsi_structured = "structured"
    pkg.extra_properties = _build_extra_properties(pkg)
    # Original-Maintainer is only known after AptCacheEnricher runs (it's not
    # in dpkg-query's output), so supplier_contacts is derived there.


class DpkgCollector(Collector):
    """Collect installed packages via dpkg-query."""

    name = "dpkg"

    def __init__(self, installed_only: bool = True, distro: str | None = None) -> None:
        self._installed_only = installed_only
        self._distro = distro

    def collect(self) -> list[PackageRecord]:
        fmt = _build_format_string()
        try:
            result = subprocess.run(
                ["dpkg-query", "-W", f"--showformat={fmt}"],
                capture_output=True, text=True, check=True,
            )
        except FileNotFoundError:
            raise RuntimeError("dpkg-query not found — is this a Debian/Ubuntu system?")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"dpkg-query failed: {e.stderr.strip()}") from e

        packages: list[PackageRecord] = []
        for block in result.stdout.split(_RECORD_SEP):
            block = block.strip()
            if not block:
                continue
            raw = _parse_record(block)
            if not raw.get("package"):
                continue
            if self._installed_only:
                if raw.get("status_want") != "install" or raw.get("status_status") != "installed":
                    continue
            packages.append(_to_record(raw))

        # PURLs, CycloneDX type/scope/properties, and the dependency graph are
        # all ecosystem facts, so the collector owns them: the formatter just
        # emits these fields verbatim.
        distro, codename = _resolve_distro(self._distro, get_os_info())
        for pkg in packages:
            _fill_purls(pkg, distro, codename)
            _fill_output_mapping(pkg)
        _resolve_dependencies(packages)

        logger.info("  <- %d packages found", len(packages))
        return packages
