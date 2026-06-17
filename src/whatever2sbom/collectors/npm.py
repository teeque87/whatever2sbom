import base64
import binascii
import json
import logging
from pathlib import Path

from whatever2sbom.collectors.base import Collector
from whatever2sbom.models import PackageRecord
from whatever2sbom.util import purl as _purl

logger = logging.getLogger(__name__)

# lockfileVersion 2 and 3 both key installed packages under the `packages` map
# (v3 dropped the legacy `dependencies` tree v2 still carried for npm 6
# compatibility). v1 (npm <= 6) only has the nested `dependencies` tree and is
# not supported. A future v4 would slot in here once its `packages` shape is
# known — like a new CycloneDX spec version on the formatter side.
_SUPPORTED_LOCKFILE_VERSIONS = (2, 3)


# Lockfile names tried (in order) when --lockfile names a directory or isn't
# given. npm also maintains a copy inside node_modules ("hidden" lockfile, same
# lockfileVersion 3 format), which is a useful fallback when the top-level one
# is absent but the tree is installed.
_LOCKFILE_NAMES = ("package-lock.json", "node_modules/.package-lock.json")


def _find_lockfile(lockfile: str | None) -> Path:
    """Resolve the npm lockfile to read.

    `--lockfile` may point at the file itself or at a directory to search (so
    `--lockfile path/to/project` works like a project root). With no value, the
    current directory is searched. Directory/no-value searches try
    package-lock.json first, then node_modules/.package-lock.json.
    """
    if lockfile:
        p = Path(lockfile)
        if p.is_file():
            return p
        if p.is_dir():
            if found := _search_lockfile(p):
                return found
            raise RuntimeError(
                f"no npm lockfile under {p} (looked for {', '.join(_LOCKFILE_NAMES)})"
            )
        raise RuntimeError(f"npm lockfile not found: {p}")

    if found := _search_lockfile(Path(".")):
        return found
    raise RuntimeError(
        f"no npm lockfile in current directory (looked for {', '.join(_LOCKFILE_NAMES)}) "
        "— pass --lockfile"
    )


def _search_lockfile(base: Path) -> Path | None:
    for rel in _LOCKFILE_NAMES:
        candidate = base / rel
        if candidate.is_file():
            return candidate
    return None


def _filename_from_resolved(resolved: str | None) -> str | None:
    """The deployable artifact's filename from a lockfile entry's `resolved`
    tarball URL (e.g. ".../hash-9.1.1.tgz" -> "hash-9.1.1.tgz").

    Only registry/HTTP tarballs are used; git/file/link `resolved` values have
    no meaningful artifact filename and are skipped.
    """
    if not resolved:
        return None
    path = resolved.split("#", 1)[0].split("?", 1)[0]
    name = path.rsplit("/", 1)[-1]
    return name if name.endswith((".tgz", ".tar.gz")) else None


def _package_name_from_path(path: str) -> str:
    """The installed package name is the path segment after the last
    `node_modules/` — which keeps the scope for scoped packages
    ("node_modules/@scope/pkg" -> "@scope/pkg") and drops the parent chain for
    nested (deduped) installs ("node_modules/a/node_modules/b" -> "b")."""
    return path.split("node_modules/")[-1]


def _hashes_from_integrity(integrity: str | None) -> dict[str, str]:
    """Decode an SRI `integrity` string ("sha512-<base64>", possibly several
    space-separated) into {algorithm: hex digest}.

    npm stores the digest base64-encoded; CycloneDX hash `content` is the hex
    digest, so it's decoded and re-encoded here.
    """
    out: dict[str, str] = {}
    for token in (integrity or "").split():
        alg, _, b64 = token.partition("-")
        if not b64:
            continue
        try:
            out[alg.lower()] = base64.b64decode(b64).hex()
        except (binascii.Error, ValueError):
            continue
    return out


def _extract_licenses(entry: dict) -> list[str]:
    """Pull declared license(s) from a lockfile entry.

    Modern lockfiles use a `license` SPDX-expression string; older/published
    metadata may use a `license` object ({type, url}), a list of such objects,
    or the legacy plural `licenses` array. "UNLICENSED" (npm's marker for
    proprietary / no license) is dropped rather than emitted as a license.
    """
    lic = entry.get("license")
    raw: list[str] = []
    if isinstance(lic, str):
        raw = [lic]
    elif isinstance(lic, dict) and lic.get("type"):
        raw = [lic["type"]]
    elif isinstance(lic, list):
        raw = [x["type"] for x in lic if isinstance(x, dict) and x.get("type")]
    elif isinstance(entry.get("licenses"), list):
        raw = [x["type"] for x in entry["licenses"] if isinstance(x, dict) and x.get("type")]
    return [s for s in raw if s and s.upper() != "UNLICENSED"]


def _is_dev(entry: dict) -> bool:
    """True if the entry is only present for development.

    `devOptional` means "a dev dependency that is also optional" — still a dev
    dependency, so it is dropped under --exclude-dev-dependencies too.
    """
    return bool(entry.get("dev") or entry.get("devOptional"))


def _scope_for(entry: dict) -> str:
    """Map npm install flags to a CycloneDX component scope.

    Dev-only packages are present in node_modules but not in the deployed
    runtime, so they're marked "excluded"; npm optional deps -> "optional";
    everything else -> "required".
    """
    if _is_dev(entry):
        return "excluded"
    if entry.get("optional"):
        return "optional"
    return "required"


def _to_record(name: str, version: str, entry: dict) -> PackageRecord:
    pkg = PackageRecord(name=name, version=version)
    pkg.purl = _purl.npm(name, version)
    pkg.bom_ref = pkg.purl
    pkg.component_type = "library"
    pkg.scope = _scope_for(entry)
    pkg.licenses = _extract_licenses(entry)
    pkg.filename = _filename_from_resolved(entry.get("resolved"))

    hashes = _hashes_from_integrity(entry.get("integrity"))
    pkg.sha512 = hashes.get("sha512")
    pkg.sha256 = hashes.get("sha256")
    pkg.sha1 = hashes.get("sha1")

    # An installed npm package is an unpacked directory of JS/JSON files run by
    # the Node runtime — not itself an executable archive. A `bin` entry makes
    # it directly invokable.
    pkg.bsi_executable = "executable" if entry.get("bin") else "non-executable"
    pkg.bsi_archive = "non-archive"
    pkg.bsi_structured = "structured"

    deprecated = entry.get("deprecated")
    if deprecated:
        pkg.extra_properties.append(
            ("npm:deprecated", deprecated if isinstance(deprecated, str) else "true")
        )
    return pkg


def _candidate_node_modules(path: str) -> list[str]:
    """The node_modules directories Node would search for a dependency of the
    package installed at `path`, closest (the package's own) first, walking up
    the tree toward the project root."""
    dirs: list[str] = []
    p = path
    while True:
        dirs.append(f"{p}/node_modules" if p else "node_modules")
        if not p:
            break
        idx = p.rfind("/node_modules/")
        p = p[:idx] if idx != -1 else ""
    return dirs


def _resolve(path: str, dep_name: str, packages: dict) -> str | None:
    """Resolve `dep_name` required by the package at `path` to the lockfile key
    of the installed package that satisfies it, mirroring Node's module
    resolution (nearest node_modules first, then up to the root)."""
    for node_modules in _candidate_node_modules(path):
        candidate = f"{node_modules}/{dep_name}"
        if candidate in packages:
            return candidate
    return None


def _resolve_dependencies(
    raw_packages: dict,
    path_to_ref: dict[str, str],
    records: dict[str, PackageRecord],
) -> None:
    """Fill each package's dependency_refs from its `dependencies` /
    `optionalDependencies`, resolved against the actually-installed tree.

    peerDependencies are intentionally not graph edges: they're constraints on
    the consumer's tree (usually satisfied by an already-listed package), not
    "this package installed that one". The root project entry ("") is skipped —
    it is the product (metadata.component), not a node in the graph.
    """
    for path, entry in raw_packages.items():
        if path == "":
            continue
        src_ref = path_to_ref.get(path)
        if src_ref is None:
            continue  # excluded entry (e.g. --exclude-dev-dependencies)

        dep_names = list(entry.get("dependencies", {})) + list(
            entry.get("optionalDependencies", {})
        )
        seen: set[str] = set()
        refs: list[str] = []
        for dep_name in dep_names:
            resolved = _resolve(path, dep_name, raw_packages)
            if resolved is None:
                continue
            ref = path_to_ref.get(resolved)
            if ref and ref != src_ref and ref not in seen:
                seen.add(ref)
                refs.append(ref)
        records[src_ref].dependency_refs = refs


class NpmCollector(Collector):
    """Collect installed Node.js packages from an npm package-lock.json."""

    name = "npm"

    def __init__(self, lockfile: str | None = None, exclude_dev: bool = False) -> None:
        self._lockfile = lockfile
        self._exclude_dev = exclude_dev

    def collect(self) -> list[PackageRecord]:
        lockfile = _find_lockfile(self._lockfile)
        logger.info("  reading %s", lockfile)
        data = json.loads(lockfile.read_text(encoding="utf-8"))

        lockfile_version = data.get("lockfileVersion")
        if lockfile_version not in _SUPPORTED_LOCKFILE_VERSIONS:
            supported = ", ".join(str(v) for v in _SUPPORTED_LOCKFILE_VERSIONS)
            raise RuntimeError(
                f"unsupported npm lockfileVersion {lockfile_version!r} in {lockfile} "
                f"(supported: {supported} — regenerate with npm >= 7)"
            )

        raw_packages = data.get("packages")
        if not raw_packages:
            raise RuntimeError(
                f"{lockfile} has no 'packages' section — not a valid "
                f"lockfileVersion {lockfile_version} file?"
            )

        # bom-refs (= PURLs) can collide only for the same name@version installed
        # at two paths, which npm dedupes away; records is keyed by ref to fold
        # any such duplicate into one component while order preserves first-seen.
        path_to_ref: dict[str, str] = {}
        records: dict[str, PackageRecord] = {}
        order: list[str] = []

        for path, entry in raw_packages.items():
            # The root project ("") is the product, not an installed dependency;
            # `link` entries are symlinks to workspaces, not real installs.
            if path == "" or entry.get("link"):
                continue
            if self._exclude_dev and _is_dev(entry):
                continue
            version = entry.get("version")
            if not version:
                continue
            name = _package_name_from_path(path)
            pkg = _to_record(name, version, entry)
            ref = pkg.bom_ref or ""
            path_to_ref[path] = ref
            if ref not in records:
                records[ref] = pkg
                order.append(ref)

        _resolve_dependencies(raw_packages, path_to_ref, records)

        packages = [records[ref] for ref in order]
        logger.info("  <- %d packages found", len(packages))
        return packages
