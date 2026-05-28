"""
Extract license identifiers from /usr/share/doc/<pkg>/copyright files.

Supports DEP-5 machine-readable format. Falls back silently for packages
that use old-style free-form copyright files.
"""

import logging
from pathlib import Path

from whatever2sbom.enrichers.base import Enricher
from whatever2sbom.models import PackageRecord

logger = logging.getLogger(__name__)

_COPYRIGHT_BASE = Path("/usr/share/doc")

# Debian DEP-5 name → SPDX identifier for the most common licenses.
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


def _parse_dep5(content: str) -> list[str]:
    """
    Return unique license short-names from a DEP-5 copyright file.

    Collects licenses from all Files: stanzas. The stanza with Files: *
    is placed first when present.
    """
    stanzas: list[dict[str, str]] = []
    current: dict[str, str] = {}
    current_field: str | None = None
    current_value: list[str] = []

    def _flush_field() -> None:
        if current_field:
            current[current_field] = " ".join(current_value).strip()

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
    result: list[str] = []

    def _collect(stanza: dict[str, str]) -> None:
        raw = stanza.get("license", "")
        if not raw:
            return
        short = raw.split()[0].rstrip(";").strip()
        if short and short not in seen:
            seen.add(short)
            result.append(short)

    # Files: * stanza first for deterministic ordering
    for stanza in stanzas:
        if stanza.get("files", "").strip() == "*":
            _collect(stanza)
    for stanza in stanzas:
        if stanza.get("files", "").strip() != "*":
            _collect(stanza)

    return result


def _read_licenses(pkg_name: str) -> list[str]:
    path = _COPYRIGHT_BASE / pkg_name / "copyright"
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except (FileNotFoundError, PermissionError):
        return []

    # DEP-5 files start with a Format: header
    if content.lstrip().startswith("Format:") or "Format: https://www.debian.org" in content[:512]:
        names = _parse_dep5(content)
        return [_DEBIAN_TO_SPDX.get(n, n) for n in names]

    return []


class CopyrightEnricher(Enricher):
    """Populate PackageRecord.licenses from /usr/share/doc/<pkg>/copyright."""

    name = "copyright"

    def enrich(self, packages: list[PackageRecord]) -> list[PackageRecord]:
        found = 0
        for pkg in packages:
            licenses = _read_licenses(pkg.name)
            if licenses:
                pkg.licenses = licenses
                found += 1
        logger.info("copyright: resolved licenses for %d/%d packages", found, len(packages))
        return packages
