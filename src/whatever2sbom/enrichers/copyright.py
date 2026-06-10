"""
Extract license identifiers from /usr/share/doc/<pkg>/copyright files.

Supports DEP-5 machine-readable format, with a best-effort fallback for
old-style free-form copyright files based on standard FSF license-grant
boilerplate.
"""

import logging
import re
from pathlib import Path

from whatever2sbom.enrichers.base import Enricher
from whatever2sbom.models import PackageRecord

logger = logging.getLogger(__name__)

_COPYRIGHT_BASE = Path("/usr/share/doc")

# Debian DEP-5 name -> SPDX identifier for the most common licenses.
# Only entries where we are confident about the mapping are included;
# unmapped names are passed through as-is using the `name` field.
_DEBIAN_TO_SPDX: dict[str, str] = {
    "GPL-1":                "GPL-1.0-only",
    "GPL-1+":               "GPL-1.0-or-later",
    "GPL-2":                "GPL-2.0-only",
    "GPL-2+":               "GPL-2.0-or-later",
    "GPL-2.0-only":         "GPL-2.0-only",
    "GPL-2.0-or-later":     "GPL-2.0-or-later",
    "GPL-3":                "GPL-3.0-only",
    "GPL-3+":               "GPL-3.0-or-later",
    "GPL-3.0-only":         "GPL-3.0-only",
    "GPL-3.0-or-later":     "GPL-3.0-or-later",
    "LGPL-2":               "LGPL-2.0-only",
    "LGPL-2+":              "LGPL-2.0-or-later",
    "LGPL-2.1":             "LGPL-2.1-only",
    "LGPL-2.1+":            "LGPL-2.1-or-later",
    "LGPL-3":               "LGPL-3.0-only",
    "LGPL-3+":              "LGPL-3.0-or-later",
    "AGPL-3":               "AGPL-3.0-only",
    "AGPL-3+":              "AGPL-3.0-or-later",
    "AGPL-3.0-only":        "AGPL-3.0-only",
    "AGPL-3.0-or-later":    "AGPL-3.0-or-later",
    "Apache-2":             "Apache-2.0",
    "Apache-2.0":           "Apache-2.0",
    "MIT":                  "MIT",
    "ISC":                  "ISC",
    "BSD-2-clause":         "BSD-2-Clause",
    "BSD-3-clause":         "BSD-3-Clause",
    "BSD-4-clause":         "BSD-4-Clause",
    "MPL-1.1":              "MPL-1.1",
    "MPL-2":                "MPL-2.0",
    "MPL-2.0":              "MPL-2.0",
    "Artistic":             "Artistic-1.0",
    "Artistic-1.0":         "Artistic-1.0",
    "Artistic-2.0":         "Artistic-2.0",
    "CC0-1.0":              "CC0-1.0",
    "CC-BY-4.0":            "CC-BY-4.0",
    "CC-BY-SA-4.0":         "CC-BY-SA-4.0",
    "Unlicense":            "Unlicense",
    "WTFPL":                "WTFPL",
    "Zlib":                 "Zlib",
    "PSF-2":                "PSF-2.0",
    "PSF-2.0":              "PSF-2.0",
}


def _parse_dep5(content: str) -> tuple[list[str], str | None]:
    """
    Return (unique license short-names, copyright notice) from a DEP-5
    copyright file.

    Collects from all Files: stanzas. The stanza with Files: * is considered
    first when present, since it covers the whole package.
    """
    stanzas: list[dict[str, str]] = []
    current: dict[str, str] = {}
    current_field: str | None = None
    current_value: list[str] = []

    def _flush_field() -> None:
        if current_field:
            # Preserve line breaks: a Copyright field commonly lists one
            # holder/year range per line, and joining with spaces would
            # smash them into an unreadable run-on. "license".split()[0]
            # is unaffected, since str.split() treats "\n" as whitespace.
            current[current_field] = "\n".join(current_value).strip()

    def _flush_stanza() -> None:
        _flush_field()
        if current:
            stanzas.append(dict(current))
        current.clear()

    for line in content.splitlines():
        if line == "" or line == ".":
            _flush_stanza()
            current_field = None
            current_value = []
            continue
        if line[0] in (" ", "\t"):
            stripped = line.strip()
            if stripped and stripped != ".":
                current_value.append(stripped)
            continue
        if ":" in line:
            _flush_field()
            key, _, value = line.partition(":")
            current_field = key.strip().lower()
            current_value = [value.strip()]

    _flush_stanza()

    seen: set[str] = set()
    licenses: list[str] = []
    notice: str | None = None

    def _collect(stanza: dict[str, str]) -> None:
        nonlocal notice
        raw = stanza.get("license", "")
        if raw:
            short = raw.split()[0].rstrip(";").strip()
            if short and short not in seen:
                seen.add(short)
                licenses.append(short)
        if notice is None:
            text = stanza.get("copyright", "").strip()
            if text:
                notice = text

    # Files: * stanza first for deterministic ordering
    for stanza in stanzas:
        if stanza.get("files", "").strip() == "*":
            _collect(stanza)
    for stanza in stanzas:
        if stanza.get("files", "").strip() != "*":
            _collect(stanza)

    return licenses, notice


# Standard FSF license-grant families: their full name, or the bare
# abbreviation (e.g. "GNU LGPL version 2", "licensed under the LGPL").
# `\b...\b` keeps "GPL" from matching inside "LGPL"/"AGPL" -- there's no word
# boundary between the leading "L"/"A" and "G".
_FSF_LICENSE_FAMILIES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"GNU\s+Affero\s+General\s+Public\s+License|\bAGPL\b"), "AGPL"),
    (re.compile(r"GNU\s+(?:Lesser|Library)\s+General\s+Public\s+License|\bLGPL\b"), "LGPL"),
    (re.compile(r"GNU\s+General\s+Public\s+License|\bGPL\b"), "GPL"),
    (re.compile(r"GNU\s+Free\s+Documentation\s+License|\bGFDL\b"), "GFDL"),
]

_FSF_VERSION_RE = re.compile(r"[Vv]ersion\s+(\d+(?:\.\d+)?)")
_FSF_OR_LATER_RE = re.compile(r"any later version|or later", re.IGNORECASE)

# How far past a license-family name to look for its version number and "or
# later" wording -- FSF boilerplate states both within the same sentence,
# e.g. "...either version 3 of the License, or (at your option) any later
# version."
_FSF_WINDOW = 250


def _normalize_fsf_version(version: str) -> str:
    return version if "." in version else f"{version}.0"


def _extract_fsf_licenses(content: str) -> list[str]:
    """
    Best-effort extraction of SPDX ids from old-style (non-DEP-5) copyright
    files, by recognizing the standard FSF license-grant boilerplate (e.g.
    "...under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or (at
    your option) any later version.").

    References to licenses without an accompanying version (e.g. a bare
    "/usr/share/common-licenses/LGPL" pointer) are not matched -- there's no
    reliable way to tell which version applies.
    """
    found: list[str] = []
    seen: set[str] = set()
    for pattern, prefix in _FSF_LICENSE_FAMILIES:
        for match in pattern.finditer(content):
            window = content[match.end(): match.end() + _FSF_WINDOW]
            # Don't read into the next paragraph -- a license name with no
            # version of its own (e.g. a bare common-licenses pointer) could
            # otherwise pick up an unrelated version mentioned later on.
            para_break = window.find("\n\n")
            if para_break != -1:
                window = window[:para_break]
            version_match = _FSF_VERSION_RE.search(window)
            if not version_match:
                continue
            version = _normalize_fsf_version(version_match.group(1))
            suffix = "or-later" if _FSF_OR_LATER_RE.search(window) else "only"
            spdx_id = f"{prefix}-{version}-{suffix}"
            if spdx_id not in seen:
                seen.add(spdx_id)
                found.append(spdx_id)
    return found


def _is_dep5(content: str) -> bool:
    """
    True if `content` is a DEP-5 machine-readable copyright file.

    DEP-5 files start with a "Format:" field naming the spec. Older drafts
    used "Format-Specification:" instead, with URLs other than the current
    https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/ (e.g.
    "http://svn.debian.org/wsvn/dep/web/deps/dep5.mdwn?rev=59"), so match on
    the field name only rather than a specific URL.
    """
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        return stripped.lower().startswith(("format:", "format-specification:"))
    return False


def _read_package_metadata(pkg_name: str) -> tuple[list[str], str | None]:
    path = _COPYRIGHT_BASE / pkg_name / "copyright"
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except (FileNotFoundError, PermissionError):
        return [], None

    if _is_dep5(content):
        names, notice = _parse_dep5(content)
        return [_DEBIAN_TO_SPDX.get(n, n) for n in names], notice

    return _extract_fsf_licenses(content), None


class CopyrightEnricher(Enricher):
    """Populate PackageRecord.licenses from /usr/share/doc/<pkg>/copyright."""

    name = "copyright"

    def enrich(self, packages: list[PackageRecord]) -> list[PackageRecord]:
        found = 0
        for pkg in packages:
            licenses, copyright_notice = _read_package_metadata(pkg.name)
            if licenses:
                pkg.licenses = licenses
                found += 1
            if copyright_notice:
                pkg.copyright = copyright_notice
        logger.info("  <- %d / %d licenses resolved", found, len(packages))
        return packages
