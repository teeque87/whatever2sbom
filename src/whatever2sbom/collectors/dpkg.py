import fnmatch
import logging
import re
import subprocess
from collections import Counter
from pathlib import Path

from whatever2sbom.collectors.base import Collector
from whatever2sbom.models import SOURCE_PSEUDO_COMPONENT_PROPERTY, PackageRecord
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


def _fill_bom_ref(pkg: PackageRecord, distro: str, codename: str | None) -> None:
    """Fill the unique bom_ref (dep-graph node id) for one package.

    bom_ref is the per-binary coordinate (name + arch); it is always unique per
    installed binary and carries the binary architecture, so the dependency
    graph stays intact regardless of how the matchable PURL is assigned.
    """
    pkg.bom_ref = _purl.deb(distro, pkg.name, pkg.version, pkg.architecture or "", codename)


def _fill_purl(pkg: PackageRecord, distro: str, codename: str | None) -> None:
    """Fill the matchable PURL for one package.

    OSV/Ubuntu security advisories are keyed on the *source* package name with
    arch=source (see docs/output.md), so the rule is per-package:

    - A package that is its own source (source name == binary name, or no
      distinct source) keeps the source coordinate (arch=source) — OSV matches
      its CVEs.
    - A binary built from a *different* source uses its own binary coordinate
      plus an informational `upstream=<source>` qualifier. OSV does not match on
      binary names or the upstream qualifier, so this binary never re-matches
      the shared source advisory — which is what stops one source-level CVE from
      being reported once per binary (python3.12, python3.12-minimal,
      libpython3.12-stdlib, … no longer all duplicate the same finding).

    When a source package ships no binary of the same name (e.g.
    nvidia-graphics-drivers-590 → libnvidia-cfg1-590, …; glibc → libc6), none of
    its installed binaries hit the first branch, so none carry the source
    coordinate. _build_pseudo_sources adds a single logical source component for
    those groups so their advisories still match.
    """
    src_name = pkg.source_name or pkg.name
    if src_name == pkg.name:
        src_ver = pkg.source_version or pkg.version
        pkg.purl = _purl.deb(distro, pkg.name, src_ver, "source", codename)
    else:
        pkg.purl = _purl.deb(
            distro, pkg.name, pkg.version, pkg.architecture or "",
            codename, upstream=src_name,
        )


def _build_pseudo_sources(
    packages: list[PackageRecord], distro: str, codename: str | None
) -> list[PackageRecord]:
    """Synthesize one logical "source" component per source package that has no
    installed binary of the same name.

    OSV/Ubuntu/Debian advisories are keyed on the source package with
    arch=source, but a source like `nvidia-graphics-drivers-590` or
    `linux-hwe-6.17` may ship only differently-named binaries
    (`libnvidia-cfg1-590`, `linux-image-unsigned-…`). Without a same-named
    binary, _fill_purl gives none of them the source coordinate, so their CVEs
    can't match at all (the documented best-effort gap). For those groups we add
    one logical component carrying the source coordinate, so detection works
    while real binaries keep their own unique coordinates (no per-binary dupes).

    A pseudo-component is not an installed artifact: it has no file, hash, or
    licence. It inherits the packaging metadata its binaries share (maintainer,
    homepage) so it stays a faithful, attributable node, and is marked with a
    property so the formatter and BSI validator treat it as a logical node.
    Groups that already contain a same-named binary need no pseudo-component —
    that binary is the carrier.
    """
    groups: dict[str, list[PackageRecord]] = {}
    for pkg in packages:
        groups.setdefault(pkg.source_name or pkg.name, []).append(pkg)

    pseudo: list[PackageRecord] = []
    for src_name, members in groups.items():
        if any(m.name == src_name for m in members):
            continue  # a same-named binary already carries the source coordinate

        # Members of one source group normally share a source version; pick the
        # one most of them agree on (robust against a partial-upgrade skew).
        versions = [m.source_version or m.version for m in members]
        src_ver = Counter(versions).most_common(1)[0][0]
        coord = _purl.deb(distro, src_name, src_ver, "source", codename)
        covered = ", ".join(sorted(m.name for m in members))

        pseudo.append(PackageRecord(
            name=src_name,
            version=src_ver,
            source_name=src_name,
            source_version=src_ver,
            maintainer=next((m.maintainer for m in members if m.maintainer), None),
            homepage=next((m.homepage for m in members if m.homepage), None),
            description=f"Source package for: {covered}",
            purl=coord,
            bom_ref=coord,
            component_type="library",
            scope="required" if any(m.scope == "required" for m in members) else "optional",
            extra_properties=[(SOURCE_PSEUDO_COMPONENT_PROPERTY, "true")],
        ))
    return pseudo


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


# package exclusion (--exclude / --exclude-file)

_GLOB_CHARS = frozenset("*?[")


def _is_glob(pattern: str) -> bool:
    return any(c in _GLOB_CHARS for c in pattern)


def read_exclude_file(path: str) -> list[str]:
    """Read newline-separated exclusion patterns from a file.

    Blank lines and `#` comments (whole-line or trailing) are ignored, and
    surrounding whitespace is trimmed — so the list can be annotated with the
    reason for each entry. dpkg package names never contain `#`, so splitting on
    it is safe.
    """
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as e:
        raise RuntimeError(f"could not read --exclude-file {path!r}: {e}") from e
    patterns: list[str] = []
    for line in text.splitlines():
        entry = line.split("#", 1)[0].strip()
        if entry:
            patterns.append(entry)
    return patterns


class _ExcludeFilter:
    """Match package names against exclusion patterns.

    A pattern with a glob metacharacter (`*`, `?`, `[`) is matched with
    case-sensitive `fnmatch` (e.g. `linux-image-*`, `*-dbg`); every other
    pattern is an exact name match. Matching against the bare package name (the
    collector already strips any `:arch` qualifier) keeps exclusion predictable —
    a destructive operation, so it never does surprising prefix matching.
    """

    def __init__(self, patterns: list[str]) -> None:
        # Preserve order, drop duplicates — used for the "matched nothing" report.
        self._patterns = list(dict.fromkeys(patterns))
        self._exact = {p for p in self._patterns if not _is_glob(p)}
        self._globs = [p for p in self._patterns if _is_glob(p)]
        self.matched: set[str] = set()
        self.removed = 0

    def _hit(self, name: str) -> str | None:
        if name in self._exact:
            return name
        return next((g for g in self._globs if fnmatch.fnmatchcase(name, g)), None)

    def keep(self, packages: list[PackageRecord]) -> list[PackageRecord]:
        """Return the packages that are *not* excluded, recording what matched."""
        kept: list[PackageRecord] = []
        for pkg in packages:
            hit = self._hit(pkg.name)
            if hit is None:
                kept.append(pkg)
            else:
                self.matched.add(hit)
                self.removed += 1
        return kept

    def unmatched(self) -> list[str]:
        """Patterns that excluded nothing — surfaced as a warning (likely typos)."""
        return [p for p in self._patterns if p not in self.matched]


class DpkgCollector(Collector):
    """Collect installed packages via dpkg-query."""

    name = "dpkg"

    def __init__(
        self,
        installed_only: bool = True,
        distro: str | None = None,
        exclude: list[str] | None = None,
        exclude_file: str | None = None,
    ) -> None:
        self._installed_only = installed_only
        self._distro = distro
        self._exclude = exclude
        self._exclude_file = exclude_file

    def _make_exclude_filter(self) -> _ExcludeFilter | None:
        """Merge inline --exclude patterns with any --exclude-file entries.

        The file is read here (not in the CLI layer) so a read error surfaces as
        a clean pipeline RuntimeError alongside other collector failures."""
        patterns = list(self._exclude or [])
        if self._exclude_file:
            patterns += read_exclude_file(self._exclude_file)
        return _ExcludeFilter(patterns) if patterns else None

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

        # Drop excluded packages up front, before the dependency graph and the
        # synthetic source components are built: dependency edges to an excluded
        # package are then never resolved (no dangling refs), and a source group
        # emptied by exclusion produces no pseudo-component.
        exclude = self._make_exclude_filter()
        if exclude is not None:
            packages = exclude.keep(packages)

        # PURLs, CycloneDX type/scope/properties, and the dependency graph are
        # all ecosystem facts, so the collector owns them: the formatter just
        # emits these fields verbatim.
        distro, codename = _resolve_distro(self._distro, get_os_info())
        for pkg in packages:
            _fill_bom_ref(pkg, distro, codename)
            _fill_purl(pkg, distro, codename)
            _fill_output_mapping(pkg)

        # Add logical "source" components for source packages with no same-named
        # binary, so their advisories are still matchable. Done after the per-
        # package pass (their fields are set directly, not via _fill_*). The
        # exclusion filter is applied to them too — nothing depends on a pseudo
        # component and they declare no dependencies, so dropping one is safe —
        # so excluding a source by name (or glob) removes its pseudo-component.
        pseudo = _build_pseudo_sources(packages, distro, codename)
        if exclude is not None:
            pseudo = exclude.keep(pseudo)
        packages.extend(pseudo)

        _resolve_dependencies(packages)

        if exclude is not None:
            unmatched = exclude.unmatched()
            if unmatched:
                logger.warning(
                    "exclude: %d pattern(s) matched no package: %s",
                    len(unmatched), ", ".join(unmatched),
                )
            logger.info("  -- excluded %d package(s)", exclude.removed)

        logger.info("  <- %d packages found (+%d source components)", len(packages) - len(pseudo), len(pseudo))
        return packages
