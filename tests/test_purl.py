"""Unit tests for PURL building and dpkg PURL assignment."""

import pytest

from whatever2sbom.util.purl import deb, pypi, quote_version
from whatever2sbom.collectors.dpkg import _assign_purls, _fill_bom_ref, _resolve_distro
from whatever2sbom.models import PackageRecord


# quote_version

@pytest.mark.parametrize("version, expected", [
    ("1.0",                  "1.0"),
    ("1.0-1ubuntu1",         "1.0-1ubuntu1"),
    ("1.0+dfsg-1",           "1.0%2Bdfsg-1"),
    ("2:1.02.205-2ubuntu3",  "2:1.02.205-2ubuntu3"),
    ("1.0~rc1",              "1.0~rc1"),
])
def test_quote_version(version: str, expected: str) -> None:
    assert quote_version(version) == expected


# deb() PURL builder

@pytest.mark.parametrize("distro,name,version,arch,codename,expected", [
    ("ubuntu", "poppler", "26.01.0-2build2", "source", "resolute",
     "pkg:deb/ubuntu/poppler@26.01.0-2build2?arch=source&distro=resolute"),
    ("ubuntu", "expat", "2.7.4+really-1", "source", "resolute",
     "pkg:deb/ubuntu/expat@2.7.4%2Breally-1?arch=source&distro=resolute"),
    ("ubuntu", "fonts-foo", "1.0-1", "all", "resolute",
     "pkg:deb/ubuntu/fonts-foo@1.0-1?distro=resolute"),
    ("ubuntu", "foo", "1.0-1", "", "resolute",
     "pkg:deb/ubuntu/foo@1.0-1?distro=resolute"),
    ("debian", "bar", "2.0", "amd64", None,
     "pkg:deb/debian/bar@2.0?arch=amd64"),
    ("debian", "baz", "3.0", "", None,
     "pkg:deb/debian/baz@3.0"),
])
def test_deb(distro, name, version, arch, codename, expected):
    assert deb(distro, name, version, arch, codename) == expected


@pytest.mark.parametrize("distro,name,version,arch,codename,upstream,expected", [
    ("ubuntu", "libpython3.12-stdlib", "3.12.3-1", "amd64", "resolute", "python3.12",
     "pkg:deb/ubuntu/libpython3.12-stdlib@3.12.3-1?arch=amd64&upstream=python3.12&distro=resolute"),
    ("debian", "libc6", "2.36-9", "amd64", None, "glibc",
     "pkg:deb/debian/libc6@2.36-9?arch=amd64&upstream=glibc"),
])
def test_deb_upstream(distro, name, version, arch, codename, upstream, expected):
    assert deb(distro, name, version, arch, codename, upstream=upstream) == expected


# pypi() PURL builder

@pytest.mark.parametrize("name,version,expected", [
    ("flask",    "3.1.0",  "pkg:pypi/flask@3.1.0"),
    ("foo-bar",  "1.0+local", "pkg:pypi/foo-bar@1.0%2Blocal"),
])
def test_pypi(name, version, expected):
    assert pypi(name, version) == expected


# _resolve_distro

@pytest.mark.parametrize("override,os_info,want_distro,want_codename", [
    ("ubuntu", {"id": "debian", "version_codename": "bookworm"}, "ubuntu", "bookworm"),
    (None,     {"id": "ubuntu", "version_codename": "resolute"}, "ubuntu", "resolute"),
    (None,     {},                                                "debian", None),
])
def test_resolve_distro(override, os_info, want_distro, want_codename):
    distro, codename = _resolve_distro(override, os_info)
    assert distro == want_distro
    assert codename == want_codename


# _fill_bom_ref

@pytest.mark.parametrize("pkg,want_bom_ref", [
    (
        PackageRecord(name="poppler-utils", version="26.01.0-2build2", architecture="amd64",
                      source_name="poppler", source_version="26.01.0-2build2"),
        "pkg:deb/ubuntu/poppler-utils@26.01.0-2build2?arch=amd64&distro=resolute",
    ),
    (
        PackageRecord(name="fonts-foo", version="1.0-1", architecture="all",
                      source_name="foo", source_version="1.0-1"),
        "pkg:deb/ubuntu/fonts-foo@1.0-1?distro=resolute",
    ),
])
def test_fill_bom_ref(pkg, want_bom_ref):
    _fill_bom_ref(pkg, "ubuntu", "resolute")
    assert pkg.bom_ref == want_bom_ref, f"bom_ref: got {pkg.bom_ref!r}, want {want_bom_ref!r}"


# _assign_purls — source-coordinate de-duplication across a source group

def _purl_of(packages, name):
    return next(p for p in packages if p.name == name).purl


def test_assign_purls_own_source():
    """A package that is its own source keeps the source coordinate."""
    pkg = PackageRecord(name="bash", version="5.3-2ubuntu1", architecture="amd64")
    _assign_purls([pkg], "ubuntu", "resolute")
    assert pkg.purl == "pkg:deb/ubuntu/bash@5.3-2ubuntu1?arch=source&distro=resolute"


def test_assign_purls_carrier_named_like_source():
    """The binary named like the source carries the source coordinate; the
    rest carry their binary coordinate plus upstream=<source>."""
    packages = [
        PackageRecord(name="python3.12-minimal", version="3.12.3-1", architecture="amd64",
                      source_name="python3.12", source_version="3.12.3-1"),
        PackageRecord(name="libpython3.12-stdlib", version="3.12.3-1", architecture="amd64",
                      source_name="python3.12", source_version="3.12.3-1"),
        PackageRecord(name="python3.12", version="3.12.3-1", architecture="amd64",
                      source_name="python3.12", source_version="3.12.3-1"),
    ]
    _assign_purls(packages, "ubuntu", "resolute")

    assert _purl_of(packages, "python3.12") == \
        "pkg:deb/ubuntu/python3.12@3.12.3-1?arch=source&distro=resolute"
    assert _purl_of(packages, "python3.12-minimal") == \
        "pkg:deb/ubuntu/python3.12-minimal@3.12.3-1?arch=amd64&upstream=python3.12&distro=resolute"
    assert _purl_of(packages, "libpython3.12-stdlib") == \
        "pkg:deb/ubuntu/libpython3.12-stdlib@3.12.3-1?arch=amd64&upstream=python3.12&distro=resolute"

    # Exactly one source coordinate per group — that's the whole point.
    assert sum("arch=source" in (p.purl or "") for p in packages) == 1


def test_assign_purls_no_binary_named_like_source():
    """When no installed binary matches the source name, the alphabetically-first
    member carries the source coordinate (deterministic fallback)."""
    packages = [
        PackageRecord(name="libdevmapper1.02.1", version="2:1.02.205-2ubuntu3", architecture="amd64",
                      source_name="lvm2", source_version="2.03.31-2ubuntu3"),
        PackageRecord(name="dmsetup", version="2:1.02.205-2ubuntu3", architecture="amd64",
                      source_name="lvm2", source_version="2.03.31-2ubuntu3"),
    ]
    _assign_purls(packages, "ubuntu", "resolute")

    # "dmsetup" sorts before "libdevmapper1.02.1", so it is the carrier.
    assert _purl_of(packages, "dmsetup") == \
        "pkg:deb/ubuntu/lvm2@2.03.31-2ubuntu3?arch=source&distro=resolute"
    assert _purl_of(packages, "libdevmapper1.02.1") == \
        "pkg:deb/ubuntu/libdevmapper1.02.1@2:1.02.205-2ubuntu3?arch=amd64&upstream=lvm2&distro=resolute"
