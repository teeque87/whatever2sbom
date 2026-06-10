"""Unit tests for dependency name normalisation and resolution."""

import pytest

from whatever2sbom.collectors.dpkg import (
    _normalize_dep_name,
    _resolve_deps,
)


@pytest.mark.parametrize("raw, expected", [
    ("libc6:amd64",             "libc6"),
    ("libc6 (>= 2.17)",         "libc6"),
    ("libc6 [amd64 i386]",      "libc6"),
    ("libc6:amd64 (>= 2.17)",   "libc6"),
    ("  awk  ",                  "awk"),
])
def test_normalize_dep_name(raw: str, expected: str) -> None:
    assert _normalize_dep_name(raw) == expected


def test_resolve_deps_direct_hit() -> None:
    name_to_ref = {"libc6": "pkg:deb/debian/libc6@2.36"}
    result = _resolve_deps("libc6 (>= 2.17)", name_to_ref, {})
    assert result == ["pkg:deb/debian/libc6@2.36"]


def test_resolve_deps_arch_qualifier() -> None:
    name_to_ref = {"libc6": "pkg:deb/debian/libc6@2.36"}
    result = _resolve_deps("libc6:amd64 (>= 2.17)", name_to_ref, {})
    assert result == ["pkg:deb/debian/libc6@2.36"]


def test_resolve_deps_virtual_package() -> None:
    name_to_ref = {"mawk": "pkg:deb/debian/mawk@1.3"}
    provides_map = {"awk": "pkg:deb/debian/mawk@1.3"}
    result = _resolve_deps("awk", name_to_ref, provides_map)
    assert result == ["pkg:deb/debian/mawk@1.3"]


def test_resolve_deps_alternatives_first_wins() -> None:
    name_to_ref = {"mawk": "pkg:deb/debian/mawk@1.3"}
    result = _resolve_deps("gawk | mawk | nawk", name_to_ref, {})
    assert result == ["pkg:deb/debian/mawk@1.3"]


def test_resolve_deps_multiple_groups() -> None:
    name_to_ref = {
        "libc6": "pkg:deb/debian/libc6@2.36",
        "bash":  "pkg:deb/debian/bash@5.2",
    }
    result = _resolve_deps("libc6, bash", name_to_ref, {})
    assert result == ["pkg:deb/debian/libc6@2.36", "pkg:deb/debian/bash@5.2"]
