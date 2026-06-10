import logging
import os
import re
from importlib import metadata as im
from pathlib import Path

from packaging.markers import default_environment
from packaging.requirements import Requirement

from whatever2sbom.collectors.base import Collector
from whatever2sbom.models import PackageRecord
from whatever2sbom.util import purl as _purl

logger = logging.getLogger(__name__)

_NAME_RE = re.compile(r"[-_.]+")

# "License :: OSI Approved :: <name>" / "License :: <name>" Trove classifiers
# that map unambiguously to a single SPDX identifier. Classifiers like
# "BSD License" or "Zope Public License" cover multiple SPDX variants and are
# deliberately omitted -- better to report no license than a wrong one.
_CLASSIFIER_PREFIX_RE = re.compile(r"^License\s*::\s*(OSI Approved\s*::\s*)?")

_CLASSIFIER_SPDX: dict[str, str] = {
    "MIT License": "MIT",
    "Apache Software License": "Apache-2.0",
    "ISC License (ISCL)": "ISC",
    "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "Python Software Foundation License": "PSF-2.0",
    "The Unlicense (Unlicense)": "Unlicense",
    "zlib/libpng License": "Zlib",
    "GNU General Public License v2 (GPLv2)": "GPL-2.0-only",
    "GNU General Public License v2 or later (GPLv2+)": "GPL-2.0-or-later",
    "GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "GNU General Public License v3 or later (GPLv3+)": "GPL-3.0-or-later",
    "GNU Lesser General Public License v2 (LGPLv2)": "LGPL-2.0-only",
    "GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.0-or-later",
    "GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0-only",
    "GNU Lesser General Public License v3 or later (LGPLv3+)": "LGPL-3.0-or-later",
}

# Recognize standard license boilerplate in a bundled License-File when no
# machine-readable License-Expression/classifier is declared. Matched against
# the start of the file, where these texts conventionally place their title.
_LICENSE_TEXT_SIGNATURES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^MIT License", re.I), "MIT"),
    (re.compile(r"Apache License[\s\S]{0,40}Version 2\.0", re.I), "Apache-2.0"),
    (re.compile(r"^ISC License", re.I), "ISC"),
    (re.compile(r"^The Unlicense", re.I), "Unlicense"),
    (re.compile(r"Mozilla Public License[\s\S]{0,10}Version 2\.0", re.I), "MPL-2.0"),
]

_BSD_REDISTRIBUTION_RE = re.compile(
    r"Redistribution and use in source and binary forms", re.I
)
# The clause forbidding use of contributors' names in endorsements is what
# distinguishes BSD-3-Clause from BSD-2-Clause.
_BSD_3_CLAUSE_RE = re.compile(r"endorse or promote products derived", re.I)

_LICENSE_TEXT_HEAD = 2000  # bytes of the License-File worth scanning


def _normalize(name: str) -> str:
    """PEP 503 normalization: lowercase, runs of -_. collapse to '-'."""
    return _NAME_RE.sub("-", name).lower()


def _find_venv(venv_dir: str | None, project_dir: str) -> Path:
    """Locate the virtualenv to scan.

    A directory is a virtualenv iff it contains pyvenv.cfg — that file is the
    canonical marker (PEP 405) regardless of how the venv directory is named,
    so auto-discovery scans for it instead of relying on conventional names
    like ".venv".

    $VIRTUAL_ENV is deliberately NOT consulted: whatever2sbom itself is often
    run from inside its own virtualenv, which would shadow the *target*
    project's venv. Resolution is strictly: explicit --venv-dir, then
    auto-discovery under --project-dir, then a fatal error.
    """
    if venv_dir:
        p = Path(venv_dir)
        if not (p / "pyvenv.cfg").is_file():
            raise RuntimeError(f"{p} does not look like a virtualenv (no pyvenv.cfg)")
        return p

    base = Path(project_dir)
    if (base / "pyvenv.cfg").is_file():
        return base

    candidates = sorted(
        d for d in base.iterdir() if d.is_dir() and (d / "pyvenv.cfg").is_file()
    )
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        names = ", ".join(c.name for c in candidates)
        raise RuntimeError(
            f"Multiple virtualenvs found under {base} ({names}) — pass --venv-dir to disambiguate"
        )

    raise RuntimeError(
        f"No virtualenv found under {base} (no pyvenv.cfg in it or any immediate "
        "subdirectory). Pass --venv-dir explicitly."
    )


def _site_packages(venv_dir: Path) -> Path:
    if os.name == "nt":
        candidate = venv_dir / "Lib" / "site-packages"
        if candidate.is_dir():
            return candidate
    else:
        for child in (venv_dir / "lib").glob("python*"):
            candidate = child / "site-packages"
            if candidate.is_dir():
                return candidate
    raise RuntimeError(f"Could not find site-packages under {venv_dir}")


def _project_url(meta: im.PackageMetadata, *label_keywords: str) -> str | None:
    """Find a `Project-URL` entry whose label matches any of label_keywords.

    PyPI metadata encodes these as repeated "Label, URL" headers (e.g.
    "Documentation, https://...", "Source, https://..."), so the URL must be
    split off the label rather than used as-is.
    """
    for raw in meta.get_all("Project-URL") or []:
        label, _, url = raw.partition(",")
        if any(kw in label.strip().lower() for kw in label_keywords):
            return url.strip()
    return None


def _license_from_classifiers(meta: im.PackageMetadata) -> str | None:
    """Map an unambiguous "License :: ..." Trove classifier to an SPDX id."""
    for raw in meta.get_all("Classifier") or []:
        if not raw.startswith("License"):
            continue
        label = _CLASSIFIER_PREFIX_RE.sub("", raw).strip()
        if spdx_id := _CLASSIFIER_SPDX.get(label):
            return spdx_id
    return None


def _classify_license_text(text: str) -> str | None:
    head = text[:_LICENSE_TEXT_HEAD]
    for pattern, spdx_id in _LICENSE_TEXT_SIGNATURES:
        if pattern.search(head):
            return spdx_id
    if _BSD_REDISTRIBUTION_RE.search(head):
        return "BSD-3-Clause" if _BSD_3_CLAUSE_RE.search(head) else "BSD-2-Clause"
    return None


def _license_from_files(dist: im.Distribution) -> str | None:
    """Read bundled License-File(s) and recognize standard license boilerplate.

    Per PEP 639, wheels store these under "<dist-info>/licenses/<path>"; older
    wheels may place them directly at "<dist-info>/<path>", so try both.
    """
    for filename in dist.metadata.get_all("License-File") or []:
        for candidate in (f"licenses/{filename}", filename):
            text = dist.read_text(candidate)
            if text is None:
                continue
            if spdx_id := _classify_license_text(text):
                return spdx_id
    return None


def _license(meta: im.PackageMetadata, dist: im.Distribution) -> str | None:
    """Resolve the package's declared license, preferring the PEP 639
    SPDX `License-Expression` field, falling back to the legacy free-text
    `License` field, then a known "License :: ..." classifier, then
    recognizing standard boilerplate in a bundled License-File."""
    if expr := meta.get("License-Expression"):
        return expr
    if (lic := meta.get("License")) and lic.upper() != "UNKNOWN":
        return lic
    if spdx_id := _license_from_classifiers(meta):
        return spdx_id
    return _license_from_files(dist)


def _to_record(dist: im.Distribution) -> PackageRecord:
    meta = dist.metadata
    pkg = PackageRecord(name=meta["Name"], version=meta["Version"])
    pkg.description = meta.get("Summary")
    homepage = meta.get("Home-page")
    pkg.homepage = homepage if homepage and homepage.upper() != "UNKNOWN" else (
        _project_url(meta, "homepage", "home") or _project_url(meta, "documentation")
    )
    pkg.bugs = _project_url(meta, "issue", "bug", "tracker")
    if author := (meta.get("Author") or meta.get("Author-email")):
        pkg.authors = [author]
    if lic := _license(meta, dist):
        pkg.licenses = [lic]
    return pkg


def _fill_purls(pkg: PackageRecord) -> None:
    pkg.purl = _purl.pypi(_normalize(pkg.name), pkg.version)
    pkg.bom_ref = pkg.purl


def _fill_output_mapping(pkg: PackageRecord, dist: im.Distribution) -> None:
    pkg.component_type = "library"
    pkg.scope = "required"
    # An installed distribution is unpacked .py/.pyc files run by the
    # interpreter — not itself an executable archive. A console_scripts entry
    # point makes it directly invokable.
    has_console_script = any(ep.group == "console_scripts" for ep in dist.entry_points)
    pkg.bsi_executable = "executable" if has_console_script else "non-executable"
    pkg.bsi_archive = "non-archive"
    pkg.bsi_structured = "structured"


def _dep_applies(req: Requirement, environment: dict) -> bool:
    """True if `req` applies to a normal (non-extra) install of its package.

    Requirements gated on `extra == "..."` (optional/extra dependency groups,
    very often a package's own dev/test extras such as `pytest` under
    `extra == "testing"`) are excluded: there's no reliable way to tell from
    installed metadata alone whether that extra was actually requested by
    anything, and guessing "yes" produces false edges -- including cycles
    (e.g. pluggy[testing] depends on pytest, which depends on pluggy).
    """
    return req.marker is None or req.marker.evaluate(environment)


def _resolve_dependencies(
    packages: list[PackageRecord],
    dists: list[im.Distribution],
    environment: dict,
) -> None:
    name_to_ref = {_normalize(pkg.name): pkg.bom_ref or "" for pkg in packages}

    for pkg, dist in zip(packages, dists):
        seen: set[str] = set()
        direct: list[str] = []
        for req_str in dist.requires or []:
            req = Requirement(req_str)
            if not _dep_applies(req, environment):
                continue
            ref = name_to_ref.get(_normalize(req.name))
            if ref and ref not in seen and ref != pkg.bom_ref:
                seen.add(ref)
                direct.append(ref)
        pkg.dependency_refs = direct


class PipCollector(Collector):
    """Collect installed packages from a virtualenv via importlib.metadata."""

    name = "pip"

    def __init__(self, venv_dir: str | None = None, project_dir: str = ".") -> None:
        self._venv_dir = venv_dir
        self._project_dir = project_dir

    def collect(self) -> list[PackageRecord]:
        venv = _find_venv(self._venv_dir, self._project_dir)
        site_packages = _site_packages(venv)
        logger.info("  scanning %s", site_packages)

        dists = list(im.distributions(path=[str(site_packages)]))
        packages = [_to_record(d) for d in dists]
        for pkg, dist in zip(packages, dists):
            _fill_purls(pkg)
            _fill_output_mapping(pkg, dist)

        # NOTE: markers (python_version, sys_platform, ...) are evaluated
        # against *this* interpreter's environment, not the scanned venv's.
        # Fine when scanning your own venv; a venv for a different Python
        # version/platform would need an environment built from its
        # pyvenv.cfg / python executable instead.
        _resolve_dependencies(packages, dists, default_environment())

        logger.info("  ← %d packages found", len(packages))
        return packages
